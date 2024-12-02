use libbpf_rs::MapCore;

use super::{Gpuprobe, GpuprobeError, LIBCUDART_PATH};
use std::collections::{BTreeMap, HashMap, HashSet};

/// contains implementation for the memleak program
impl Gpuprobe {
    /// attaches uprobes for the memleak program, or returns an error on
    /// failure
    pub fn attach_memleak_uprobes(&mut self) -> Result<(), GpuprobeError> {
        let cuda_malloc_uprobe_link = self
            .skel
            .skel
            .progs
            .memleak_cuda_malloc
            .attach_uprobe(false, -1, LIBCUDART_PATH, 0x00000000000560c0)
            .map_err(|_| GpuprobeError::AttachError)?;

        let cuda_malloc_uretprobe_link = self
            .skel
            .skel
            .progs
            .memleak_cuda_malloc_ret
            .attach_uprobe(true, -1, LIBCUDART_PATH, 0x00000000000560c0)
            .map_err(|_| GpuprobeError::AttachError)?;

        let cuda_free_uprobe_link = self
            .skel
            .skel
            .progs
            .trace_cuda_free
            .attach_uprobe(false, -1, LIBCUDART_PATH, 0x00000000000568c0)
            .map_err(|_| GpuprobeError::AttachError)?;

        let cuda_free_uretprobe_link = self
            .skel
            .skel
            .progs
            .trace_cuda_free_ret
            .attach_uprobe(true, -1, LIBCUDART_PATH, 0x00000000000568c0)
            .map_err(|_| GpuprobeError::AttachError)?;

        self.links.links.memleak_cuda_malloc = Some(cuda_malloc_uprobe_link);
        self.links.links.memleak_cuda_malloc_ret = Some(cuda_malloc_uretprobe_link);
        self.links.links.trace_cuda_free = Some(cuda_free_uprobe_link);
        self.links.links.trace_cuda_free_ret = Some(cuda_free_uretprobe_link);
        Ok(())
    }

    /// Consumes from the memleak event queue and updates memleak_state
    pub fn consume_memleak_events(&mut self) -> Result<(), GpuprobeError> {
        let key: [u8; 0] = []; // key size must be zero for BPF_MAP_TYPE_QUEUE
                               // `lookup_and_delete` calls.
        while let Ok(opt) = self
            .skel
            .skel
            .maps
            .memleak_events_queue
            .lookup_and_delete(&key)
        {
            let event_bytes = match opt {
                Some(b) => b,
                None => {
                    return Ok(());
                }
            };
            let event = match MemleakEvent::from_bytes(&event_bytes) {
                Some(e) => e,
                None => {
                    return Err(GpuprobeError::RuntimeError(
                        "unable to construct MemleakEvent from bytes".to_string(),
                    ));
                }
            };
            self.memleak_state.handle_event(event)?;
        }
        Ok(())
    }
}

pub struct MemleakState {
    pub memory_map: HashMap<u32, BTreeMap<u64, CudaMemoryAlloc>>,
    pub num_successful_mallocs: u64,
    pub num_failed_mallocs: u64,
    pub num_successful_frees: u64,
    pub num_failed_frees: u64,
    /// we use this to keep track of which processes are still alive, and
    /// efficiently clean up terminated processes
    active_pids: HashSet<u32>,
}

impl MemleakState {
    pub fn new() -> Self {
        return MemleakState {
            memory_map: HashMap::new(),
            num_successful_mallocs: 0u64,
            num_failed_mallocs: 0u64,
            num_successful_frees: 0u64,
            num_failed_frees: 0u64,
            active_pids: HashSet::new(),
        };
    }

    /// Handles a MemleakEvent recorded in kernel-space and updates all state.
    /// This includes
    ///     - memory map update
    ///     - number of calls for events
    ///     - number of failures
    fn handle_event(&mut self, data: MemleakEvent) -> Result<(), GpuprobeError> {
        self.active_pids.insert(data.pid.clone());
        if data.event_type == MemleakEventType::CudaMalloc as i32 {
            if data.ret != 0 {
                self.num_failed_mallocs += 1;
                return Ok(());
            } else {
                self.num_successful_mallocs += 1;
            }

            if !self.memory_map.contains_key(&data.pid) {
                self.memory_map.insert(data.pid, BTreeMap::new());
            }

            let memory_map = match self.memory_map.get_mut(&data.pid) {
                Some(mm) => mm,
                None => {
                    todo!("should return error here");
                }
            };

            memory_map.insert(
                data.device_addr,
                CudaMemoryAlloc {
                    size: data.size,
                    offset: data.device_addr,
                },
            );
        } else if data.event_type == MemleakEventType::CudaFree as i32 {
            if data.ret != 0 {
                self.num_failed_frees += 1;
                return Ok(());
            } else {
                self.num_successful_frees += 1;
            }

            if !self.memory_map.contains_key(&data.pid) {
                // Freeing data that isn't allocated. This represents a problem
                // in the user code, or in our own tracking of memory
                // allocations. It seems reasonable to want to panic here.
                panic!("attempt to free unallocated memory - aborting");
            }

            let memory_map = match self.memory_map.get_mut(&data.pid) {
                Some(mm) => mm,
                None => {
                    todo!("should return error here");
                }
            };

            // set the number of outsanding bytes to zero
            memory_map.insert(
                data.device_addr,
                CudaMemoryAlloc {
                    size: 0u64,
                    offset: data.device_addr,
                },
            );
        } else {
            return Err(GpuprobeError::RuntimeError(
                "invalid memleak event type".to_string(),
            ));
        }
        Ok(())
    }

    /// Cleans up the memory maps for all terminated processes. This is a
    /// relatively expensive operation as it involves sending `kill(0)` signals
    /// to all of the processes being monitored as an aliveness check, so it
    /// should be used sparingly.
    pub fn cleanup_terminated_processes(&mut self) -> Result<(), GpuprobeError> {
        let pids: Vec<u32> = self.active_pids.clone().into_iter().collect();
        for pid in pids {
            if MemleakState::is_process_dead(pid.clone())? {
                self.cleanup_single_terminated_process(pid.clone())?;
            }
        }
        Ok(())
    }

    /// Cleans up the memory map for a single terminated process
    fn cleanup_single_terminated_process(&mut self, pid: u32) -> Result<(), GpuprobeError> {
        // we needn't clean up a processes's memory map more than once
        if !self.active_pids.contains(&pid) {
            return Ok(());
        }

        let memory_map = match self.memory_map.get_mut(&pid) {
            Some(memory_map) => memory_map,
            None => {
                return Err(GpuprobeError::RuntimeError(
                    "no memory map for provided pid".to_string(),
                ));
            }
        };

        for (_, alloc) in memory_map {
            alloc.size = 0u64;
        }

        self.active_pids.remove(&pid);
        Ok(())
    }

    /// Returns true iff the process has terminated
    fn is_process_dead(pid: u32) -> Result<bool, GpuprobeError> {
        #[cfg(target_family = "unix")]
        {
            use nix::sys::signal::kill;
            use nix::unistd::Pid;

            match kill(Pid::from_raw(pid as i32), None) {
                Ok(_) => Ok(false),
                Err(nix::errno::Errno::ESRCH) => Ok(true),
                Err(e) => Err(GpuprobeError::RuntimeError(e.to_string())),
            }
        }
    }
}

impl std::fmt::Display for MemleakState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "num_successful_mallocs:  {}",
            self.num_successful_mallocs
        )?;
        writeln!(f, "num_failed_mallocs:      {}", self.num_failed_mallocs)?;
        writeln!(f, "num_successful_frees:    {}", self.num_successful_frees)?;
        writeln!(f, "num_failed_frees:        {}", self.num_failed_frees)?;

        writeln!(f, "per-process memory maps:")?;
        for (pid, b_tree_map) in self.memory_map.iter() {
            writeln!(f, "process {}", pid)?;

            for (_, alloc) in b_tree_map.iter() {
                writeln!(f, "\t{alloc}")?;
            }
        }
        writeln!(f)
    }
}

/// Maps one-to-one with `struct memleak_event` defined `/bpf/gpuprobe.bpf.c`.
struct MemleakEvent {
    start: u64,
    end: u64,
    device_addr: u64,
    size: u64,
    pid: u32,
    ret: i32,
    event_type: i32,
}

enum MemleakEventType {
    CudaMalloc = 0,
    CudaFree = 1,
}

impl MemleakEvent {
    /// Constructs a MemleakEvent struct from a raw byte array and returns it,
    /// or None if the byte array isn't correctly sized.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }
        // This is safe if:
        // 1. The byte array contains valid data for this struct
        // 2. The byte array is at least as large as the struct
        unsafe { Some(std::ptr::read_unaligned(bytes.as_ptr() as *const Self)) }
    }
}

impl std::fmt::Display for MemleakEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{\n")?;

        if self.event_type == 0 {
            write!(f, "\ttype: {}\n", "cudaMalloc")?;
        } else if self.event_type == 1 {
            write!(f, "\ttype: {}\n", "cudaFree")?;
        }

        write!(f, "\tsize: {}\n", self.size)?;
        write!(f, "\tpid: {}\n", self.pid)?;
        write!(f, "\tstart: {}\n", self.start)?;
        write!(f, "\tend: {}\n", self.end)?;
        write!(f, "\tdev_addr: 0x{:x}\n", self.device_addr)?;
        write!(f, "\tret: {}\n", self.ret)?;

        write!(f, "}}")
    }
}

/// wraps metadata related to a cuda memory allocation
pub struct CudaMemoryAlloc {
    pub size: u64,
    pub offset: u64,
}

impl std::fmt::Display for CudaMemoryAlloc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016x}: {} Bytes", self.offset, self.size)
    }
}
