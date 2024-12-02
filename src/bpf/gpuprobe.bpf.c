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
	void *device_addr;
	__u64 size;
	__u32 pid;
	/// contains the allocation size if event_type == CUDA_MALLOC
	int32 ret;
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
	__type(key, u32);
	__type(value, struct memleak_event);
	__uint(max_entries, 1024);
} memleak_pid_to_event SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, void **);
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
	void **dev_ptr;
	u32 pid, key0 = 0;

	e.size = (size_t)PT_REGS_PARM2(ctx);
	dev_ptr = (void **)PT_REGS_PARM1(ctx);
	pid = (u32)bpf_get_current_pid_tgid();

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
	int cuda_malloc_ret;
	u32 pid, key0 = 0;
	size_t *size, *num_failures;
	struct memleak_event *e;
	void **dev_ptr;
	void ***map_ptr;

	cuda_malloc_ret = (int)PT_REGS_RC(ctx);
	pid = (u32)bpf_get_current_pid_tgid();

	e = bpf_map_lookup_elem(&memleak_pid_to_event, &pid);
	if (!e) {
		return -1;
	}

	e->ret = cuda_malloc_ret;

	// lookup the value of `devPtr` passed to `cudaMalloc` by this process
	map_ptr = (void ***)bpf_map_lookup_elem(&memleak_pid_to_dev_ptr, &pid);
	if (!map_ptr) {
		return -1;
	}
	dev_ptr = *map_ptr;

	// read the value copied into `*devPtr` by `cudaMalloc` from userspace
	if (bpf_probe_read_user(&e->device_addr, sizeof(void *), dev_ptr)) {
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
	e.device_addr = (void **)PT_REGS_PARM1(ctx);

	return bpf_map_update_elem(&memleak_pid_to_event, &e.pid, &e, 0);
}

/// uretprobe triggered when `cudaFree` returns
SEC("uretprobe/cudaFree")
int trace_cuda_free_ret(struct pt_regs *ctx)
{
	int cuda_free_ret;
	u32 pid;
	struct memleak_event *e;
	size_t zero = 0;

	pid = (u32)bpf_get_current_pid_tgid();

	e = (struct memleak_event *)bpf_map_lookup_elem(&memleak_pid_to_event,
							&pid);
	if (!e) {
		return -1;
	}

	e->end = bpf_ktime_get_ns();
	e->ret = PT_REGS_RC(ctx);

	return bpf_map_push_elem(&memleak_events_queue, e, 0);
}

/**
 * maps a kernel function address to the number of times it has been called
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, size_t);
	__uint(max_entries, 10240);
} kernel_calls_hist SEC(".maps");

SEC("uprobe/cudaKernelLaunch")
int trace_cuda_launch_kernel(struct pt_regs *ctx)
{
	void *func;
	u64 one = 1;
	size_t *num_launches;

	func = (void *)PT_REGS_PARM1(ctx);
	if (!(num_launches = bpf_map_lookup_elem(&kernel_calls_hist, &func))) {
		bpf_map_update_elem(&kernel_calls_hist, &func, &one, 0);
	} else {
		__sync_fetch_and_add(num_launches, 1);
	}
	return 0;
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
	void *dst;
	void *src;
	size_t count;
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
	void *dst = (void *)PT_REGS_PARM1(ctx);
	void *src = (void *)PT_REGS_PARM2(ctx);
	size_t count = PT_REGS_PARM3(ctx);
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
		bpf_printk("failed to cudaMemcpy");
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

char LICENSE[] SEC("license") = "GPL";
