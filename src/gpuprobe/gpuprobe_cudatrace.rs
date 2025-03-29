mod gpuprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/gpuprobe.skel.rs"
    ));
}

use std::collections::{BTreeMap, HashMap};

use libbpf_rs::{MapCore, UprobeOpts};

use super::{
    cuda_error::{CudaError, CudaErrorT, EventType},
    Gpuprobe, GpuprobeError,
};

/// contains implementations for the cudatrace program
impl Gpuprobe {
    /// attaches uprobes for the cudatrace program, or returns an error on
    /// failure
    pub fn attach_cudatrace_uprobes(&mut self) -> Result<(), GpuprobeError> {
        let opts_launch_kernel = UprobeOpts {
            func_name: "cudaLaunchKernel".to_string(),
            retprobe: false,
            ..Default::default()
        };

        let opts_launch_kernel_ret = UprobeOpts {
            func_name: "cudaLaunchKernel".to_string(),
            retprobe: true,
            ..Default::default()
        };

        let cuda_launch_kernel_uprobe_link = self
            .skel
            .skel
            .progs
            .trace_cuda_launch_kernel
            .attach_uprobe_with_opts(-1, &self.opts.libcudart_path, 0, opts_launch_kernel)
            .map_err(|_| GpuprobeError::AttachError)?;

        let cuda_launch_kernel_uretprobe_link = self
            .skel
            .skel
            .progs
            .trace_cuda_launch_kernel_ret
            .attach_uprobe_with_opts(-1, &self.opts.libcudart_path, 0, opts_launch_kernel_ret)
            .map_err(|_| GpuprobeError::AttachError)?;

        self.links.links.trace_cuda_launch_kernel = Some(cuda_launch_kernel_uprobe_link);
        self.links.links.trace_cuda_launch_kernel_ret = Some(cuda_launch_kernel_uretprobe_link);
        Ok(())
    }

    /// Consumes from the cudatrace event queue and updates cudatrace_state
    pub fn consume_cudatrace_events(&mut self) -> Result<(), GpuprobeError> {
        let key: [u8; 0] = []; // key size must be zero for BPF_MAP_TYPE_QUEUE
                               // `lookup_and_delete` calls.
        while let Ok(opt) = self
            .skel
            .skel
            .maps
            .kernel_launch_events_queue
            .lookup_and_delete(&key)
        {
            let event_bytes = match opt {
                Some(b) => b,
                None => {
                    // empty queue
                    return Ok(());
                }
            };
            let event = match KernelLaunchEvent::from_bytes(&event_bytes) {
                Some(e) => e,
                None => {
                    return Err(GpuprobeError::RuntimeError(
                        "unable to construct MemleakEvent from bytes".to_string(),
                    ));
                }
            };

            if event.is_error() {
                println!("error-code = {}", event.ret);
                self.err_state.insert(CudaError {
                    pid: event.pid,
                    event: EventType::CudaLaunchKernel,
                    error: CudaErrorT::from_int(event.ret),
                })?;
            } else {
                self.glob_process_table.create_entry(event.pid)?;
                self.cudatrace_state.handle_event(event)?;
            }
        }

        Ok(())
    }
}

/// Represents a CUDA kernel function address as it is found in the .text
/// section of the binary running on the host. We distinguish between a raw
/// unresolved address, and a resolved symbol
pub enum KernelAddress {
    Raw(u64),
    Symbol(String),
}

impl std::fmt::Display for KernelAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelAddress::Raw(addr) => write!(f, "0x{:x}", addr),
            KernelAddress::Symbol(symbol) => write!(f, "{symbol}"),
        }
    }
}

pub struct CudatraceState {
    /// maps PID to a frequency histogram
    pub kernel_freq_hist: HashMap<u32, BTreeMap<u64, u64>>,
    pub total_kernel_launches: u64,
}

impl CudatraceState {
    pub fn new() -> Self {
        return CudatraceState {
            kernel_freq_hist: HashMap::new(),
            total_kernel_launches: 0u64,
        };
    }

    fn handle_event(&mut self, data: KernelLaunchEvent) -> Result<(), GpuprobeError> {
        self.total_kernel_launches += 1;
        if !self.kernel_freq_hist.contains_key(&data.pid) {
            self.kernel_freq_hist.insert(data.pid, BTreeMap::new());
        }

        let b_tree_map = self.kernel_freq_hist.get_mut(&data.pid).unwrap();

        if !b_tree_map.contains_key(&data.kern_offset) {
            b_tree_map.insert(data.kern_offset, 1u64);
        } else {
            *b_tree_map.get_mut(&data.kern_offset).unwrap() += 1;
        }
        Ok(())
    }
}

struct KernelLaunchEvent {
    start: u64,
    end: u64,
    kern_offset: u64,
    pid: u32,
    ret: i32,
}

impl KernelLaunchEvent {
    /// Constructs a KernelLaunchEvent struct from a raw byte array and returns
    /// it, or None if the byte array isn't correctly sized.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }
        // This is safe if:
        // 1. The byte array contains valid data for this struct
        // 2. The byte array is at least as large as the struct
        unsafe { Some(std::ptr::read_unaligned(bytes.as_ptr() as *const Self)) }
    }

    /// Return true iff the event is an error
    pub fn is_error(&self) -> bool {
        self.ret != CudaErrorT::CudaSuccess as i32
    }
}
