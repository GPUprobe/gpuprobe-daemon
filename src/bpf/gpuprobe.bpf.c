#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum memleak_event_t {
	CUDA_MALLOC = 0,
	CUDA_FREE,
};

/**
 * Wraps the arguments passed to `cudaMalloc` or `cudaFree`, and return code,
 * and some metadata
 */
struct memleak_event {
	__u64 start;
	__u64 end;
	__u64 device_addr;
	__u64 size;
	__u32 pid;
	__s32 ret;
	enum memleak_event_t event_type;
};

/**
 * Several required data and metadata fields of a memleak event can only be 
 * read from the initial uprobe, but are needed in order to emit events from
 * the uretprobe on return. We map pid to the started event, which is then
 * read and cleared from the uretprobe. This works under the assumption that
 * only one instance of either `cudaMalloc` or `cudaFree` is being executed at
 * a time per process.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct memleak_event);
	__uint(max_entries, 1024);
} memleak_pid_to_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} memleak_pid_to_dev_ptr SEC(".maps");

/**
 * Queue of memleak events that are updated from eBPF space, then dequeued
 * and processed from userspace by the GPUprobe daemon.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(key_size, 0);
	__type(value, struct memleak_event);
	__uint(max_entries, 1024);
} memleak_events_queue SEC(".maps");

/// uprobe triggered by a call to `cudaMalloc`
SEC("uprobe/cudaMalloc")
int memleak_cuda_malloc(struct pt_regs *ctx)
{
	struct memleak_event e = { 0 };
	__u64 dev_ptr;
	__u32 pid, key0 = 0;

	e.size = (__u64)PT_REGS_PARM2(ctx);
	dev_ptr = (__u64) PT_REGS_PARM1(ctx);
	pid = (__u32)bpf_get_current_pid_tgid();

	e.event_type = CUDA_MALLOC;
	e.start = bpf_ktime_get_ns();
	e.pid = pid;

	if (bpf_map_update_elem(&memleak_pid_to_event, &pid, &e, 0)) {
		return -1;
	}

	return bpf_map_update_elem(&memleak_pid_to_dev_ptr, &pid, &dev_ptr, 0);
}

/// uretprobe triggered when `cudaMalloc` returns
SEC("uretprobe/cudaMalloc")
int memleak_cuda_malloc_ret(struct pt_regs *ctx)
{
	__s32 cuda_malloc_ret;
	__u32 pid;
	struct memleak_event *e;
	__u64 dev_ptr, map_ptr;

	cuda_malloc_ret = (__s32)PT_REGS_RC(ctx);
	pid = (__u32)bpf_get_current_pid_tgid();

	e = bpf_map_lookup_elem(&memleak_pid_to_event, &pid);
	if (!e) {
		return -1;
	}

	e->ret = cuda_malloc_ret;

	// lookup the value of `devPtr` passed to `cudaMalloc` by this process
	map_ptr = (__u64)bpf_map_lookup_elem(&memleak_pid_to_dev_ptr, &pid);
	if (!map_ptr) {
		return -1;
	}
	dev_ptr = *(__u64*)map_ptr;

	// read the value copied into `*devPtr` by `cudaMalloc` from userspace
	if (bpf_probe_read_user(&e->device_addr, sizeof(void *), (void*)dev_ptr)) {
		return -1;
	}

	e->end = bpf_ktime_get_ns();

	return bpf_map_push_elem(&memleak_events_queue, e, 0);
}

/// uprobe triggered by a call to `cudaFree`
SEC("uprobe/cudaFree")
int trace_cuda_free(struct pt_regs *ctx)
{
	struct memleak_event e = { 0 };

	e.event_type = CUDA_FREE;
	e.pid = (u32)bpf_get_current_pid_tgid();
	e.start = bpf_ktime_get_ns();
	e.device_addr = (__u64)PT_REGS_PARM1(ctx);

	return bpf_map_update_elem(&memleak_pid_to_event, &e.pid, &e, 0);
}

/// uretprobe triggered when `cudaFree` returns
SEC("uretprobe/cudaFree")
int trace_cuda_free_ret(struct pt_regs *ctx)
{
	__s32 cuda_free_ret;
	__u32 pid;
	struct memleak_event *e;

	pid = (__u32)bpf_get_current_pid_tgid();

	e = (struct memleak_event *)bpf_map_lookup_elem(&memleak_pid_to_event,
							&pid);
	if (!e) {
		return -1;
	}

	e->end = bpf_ktime_get_ns();
	e->ret = PT_REGS_RC(ctx);

	return bpf_map_push_elem(&memleak_events_queue, e, 0);
}

struct kernel_launch_event {
	__u64 timestamp;
	__u64 kern_offset;
	__u32 pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(key_size, 0);
	__type(value, struct kernel_launch_event);
	__uint(max_entries, 10240);
} kernel_launch_events_queue SEC(".maps");

SEC("uprobe/cudaKernelLaunch")
int trace_cuda_launch_kernel(struct pt_regs *ctx)
{
	struct kernel_launch_event e;
	void *kern_offset;

	e.timestamp = bpf_ktime_get_ns();
	e.kern_offset = (__u64)PT_REGS_PARM1(ctx);
	e.pid = (__u32)bpf_get_current_pid_tgid();

	return bpf_map_push_elem(&kernel_launch_events_queue, &e, 0);
}

/**
 * redefinition of `enum cudaMemcpyKind` in driver_types.h.
 */
enum memcpy_kind {
	D2D = 0, // device to device
	D2H = 1, // device to host
	H2D = 2, // host to device
	H2H = 3, // host to host
	DEFAULT = 4, // inferred from pointer type at runtime
};

struct cuda_memcpy {
	__u64 start_time;
	__u64 end_time;
	__u64 dst;
	__u64 src;
	__u64 count;
	enum memcpy_kind kind;
};

/**
 * Maps a pid to an information on an incomplete cudaMemcpy call. This is 
 * needed because we cannot access the input arguments inside of the uretprobe.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct cuda_memcpy);
	__uint(max_entries, 10240);
} pid_to_memcpy SEC(".maps");

/**
 * Queue of successful cudaMemcpy calls to be processed from userspace.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(key_size, 0);
	__uint(value_size, sizeof(struct cuda_memcpy));
	__uint(max_entries, 10240);
} successful_cuda_memcpy_q SEC(".maps");

/**
 * This function exhibits synchronous behavior in MOST cases as specified by
 * Nvidia documentation. It is under the assumption that this call is 
 * synchronous that we compute the average memory bandwidth of a transfer as:
 *		avg_throughput = count /  (end - start)
 */
SEC("uprobe/cudaMemcpy")
int trace_cuda_memcpy(struct pt_regs *ctx)
{
	__u64 dst = PT_REGS_PARM1(ctx);
	__u64 src = PT_REGS_PARM2(ctx);
	__u64 count = PT_REGS_PARM3(ctx);
	enum memcpy_kind kind = PT_REGS_PARM4(ctx);
	__u32 pid = (__u32)bpf_get_current_pid_tgid();

	/* no host-side synchronization is performed in the D2D case - as a result,
	 * we cannot compute average throughput using information available from
	 * this uprobe. If the DEFAULT argument is passed, we cannot make any 
	 * assumption on the direction of the transfer */
	if (kind == D2D || kind == DEFAULT)
		return 0;

	struct cuda_memcpy in_progress_memcpy = { .start_time =
							  bpf_ktime_get_ns(),
						  .dst = dst,
						  .src = src,
						  .count = count,
						  .kind = kind };

	if (bpf_map_update_elem(&pid_to_memcpy, &pid, &in_progress_memcpy, 0)) {
		return -1;
	}

	return 0;
}

SEC("uretprobe/cudaMemcpy")
int trace_cuda_memcpy_ret(struct pt_regs *ctx)
{
	__u32 ret = PT_REGS_RC(ctx);
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	struct cuda_memcpy *exited_memcpy;

	if (ret) {
		return -1;
	}

	exited_memcpy =
		(struct cuda_memcpy *)bpf_map_lookup_elem(&pid_to_memcpy, &pid);
	if (!exited_memcpy) {
		return -1;
	}

	if (bpf_map_delete_elem(&pid_to_memcpy, &pid)) {
		return -1;
	}

	exited_memcpy->end_time = bpf_ktime_get_ns();
	if (bpf_map_push_elem(&successful_cuda_memcpy_q, exited_memcpy, 0)) {
		return -1;
	}

	return 0;
}

struct sys_enter_open_args {
    unsigned long long unused;
    long syscall_nr;
    const char *filename;
    long flags;
    long mode;
};

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct sys_enter_open_args* ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 pid = id;

	bpf_printk("process_%d -> %s", pid, ctx->filename);
    return 0;
}

struct sys_enter_openat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct sys_enter_openat_args* ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 pid = id;
	bpf_printk("process_%d -> %s", pid, ctx->filename);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
