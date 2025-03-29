pub mod cuda_error;
pub mod gpuprobe_bandwidth_util;
pub mod gpuprobe_cudatrace;
pub mod gpuprobe_memleak;
pub mod metrics;
pub mod process_state;
pub mod uprobe_data;

use chrono::Local;
use metrics::GpuprobeMetrics;
use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    OpenObject,
};

mod gpuprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/gpuprobe.skel.rs"
    ));
}
use gpuprobe::*;

use self::{cuda_error::CudaErrorState, gpuprobe_cudatrace::CudatraceState};
use self::{gpuprobe_memleak::MemleakState, process_state::GlobalProcessTable};

pub struct SafeGpuprobeLinks {
    links: GpuprobeLinks,
}

pub struct SafeGpuprobeSkel {
    // E.G: For now we settle for this questionable behavior - we are
    // interacting with eBPF skeleton, managing the lifetime of a
    // kernel-attached eBPF program. At this stage I am not sure we can do
    // better than a static lifetime on this parameter.
    skel: GpuprobeSkel<'static>,
}

pub struct SafeGpuProbeObj {
    open_obj: Box<MaybeUninit<OpenObject>>,
}

unsafe impl Send for SafeGpuprobeSkel {}
unsafe impl Sync for SafeGpuprobeSkel {}

unsafe impl Send for SafeGpuprobeLinks {}
unsafe impl Sync for SafeGpuprobeLinks {}

unsafe impl Send for SafeGpuProbeObj {}
unsafe impl Sync for SafeGpuProbeObj {}

/// Gpuuprobe wraps the eBPF program state, provides an interface for
/// attaching relevant uprobes, and exporting their metrics.
///
/// TODO: maybe consider using orobouros self-referential instead of the
/// static lifetime
pub struct Gpuprobe {
    obj: SafeGpuProbeObj,
    skel: SafeGpuprobeSkel, // references a static lifetime! See struct def
    links: SafeGpuprobeLinks,
    opts: Opts,
    pub metrics: GpuprobeMetrics,
    memleak_state: MemleakState,
    cudatrace_state: CudatraceState,
    /// maps pid to a symbol table - cached for quick symbolic resolution
    glob_process_table: GlobalProcessTable,
    err_state: CudaErrorState,
}

#[derive(Clone, Debug)]
pub struct Opts {
    pub memleak: bool,
    pub cudatrace: bool,
    pub bandwidth_util: bool,
    pub libcudart_path: String,
}

const DEFAULT_LINKS: GpuprobeLinks = GpuprobeLinks {
    memleak_cuda_malloc: None,
    memleak_cuda_malloc_ret: None,
    trace_cuda_free: None,
    trace_cuda_free_ret: None,
    trace_cuda_launch_kernel: None,
    trace_cuda_launch_kernel_ret: None,
    trace_cuda_memcpy: None,
    trace_cuda_memcpy_ret: None,
};

impl Gpuprobe {
    /// returns a new Gpuprobe, or an initialization error on failure
    pub fn new(opts: Opts) -> Result<Self, GpuprobeError> {
        let skel_builder = GpuprobeSkelBuilder::default();
        let mut open_obj = Box::new(MaybeUninit::uninit());
        let open_obj_ptr = Box::as_mut(&mut open_obj) as *mut MaybeUninit<OpenObject>;
        let open_skel = unsafe {
            skel_builder
                .open(&mut *open_obj_ptr)
                .map_err(|_| GpuprobeError::OpenError)?
        };
        let skel = open_skel.load().map_err(|_| GpuprobeError::LoadError)?;
        let metrics = GpuprobeMetrics::new(opts.clone())?;
        Ok(Self {
            obj: SafeGpuProbeObj { open_obj },
            skel: SafeGpuprobeSkel { skel },
            links: SafeGpuprobeLinks {
                links: DEFAULT_LINKS,
            },
            opts,
            metrics,
            memleak_state: MemleakState::new(),
            cudatrace_state: CudatraceState::new(),
            glob_process_table: GlobalProcessTable::new(),
            err_state: CudaErrorState::new(),
        })
    }

    /// Updates prometheus metrics registered by the GPUprobe instance
    pub fn export_open_metrics(&mut self) -> Result<(), GpuprobeError> {
        // updates memory leak stats
        if self.opts.memleak {
            // todo GC cycle for cleaning up memory maps??
            self.memleak_state.cleanup_terminated_processes()?;
            self.consume_memleak_events()?;

            for (pid, b_tree_map) in self.memleak_state.memory_map.iter() {
                for (_, alloc) in b_tree_map {
                    self.metrics
                        .memleaks
                        .get_or_create(&metrics::MemleakLabelSet {
                            pid: pid.clone(),
                            offset: alloc.offset,
                        })
                        .set(alloc.size as i64);
                }
            }
        }

        if self.opts.cudatrace {
            self.consume_cudatrace_events()?;

            for (pid, b_tree_map) in self.cudatrace_state.kernel_freq_hist.iter() {
                for (offset, count) in b_tree_map.iter() {
                    self.metrics
                        .kernel_launches
                        .get_or_create(&metrics::CudatraceLabelSet {
                            pid: pid.clone(),
                            kernel_offset: *offset,
                            kernel_symbol: match self
                                .glob_process_table
                                .resolve_symbol_text_offset(*pid, *offset)
                            {
                                Some(symbol) => symbol,
                                None => "unknown kernel".to_string(),
                            },
                        })
                        .set(*count as i64);
                }
            }
        }

        // we use `opts.memleak || self.opts.cudatrace` as a proxy for an
        // implicit option for collecting errors. By placing this at the end,
        // we ensure that all relevant events have been handled this iteration
        if self.opts.memleak || self.opts.cudatrace {
            for (pid, hash_map) in self.err_state.error_histogram.iter() {
                for ((event_type, err), count) in hash_map.iter() {
                    self.metrics
                        .err_hist
                        .get_or_create(&metrics::ErrorLabelSet {
                            pid: *pid,
                            call_type: event_type.to_string(),
                            return_code: *err as u32,
                        })
                        .set(*count as i64);
                }
            }
        }

        Ok(())
    }

    /// Displays metrics collected by the GPUprobe instance
    /// Note: this causes metrics to be recollected from the eBPF Maps, which
    /// has non-zero interference with the eBPF uprobes.
    pub fn display_metrics(&mut self) -> Result<(), GpuprobeError> {
        let now = Local::now();
        let formatted_datetime = now.format("%Y-%m-%d %H:%M:%S").to_string();
        println!("========================");
        println!("{}\n", formatted_datetime);

        if self.opts.memleak {
            self.memleak_state.cleanup_terminated_processes()?;
            self.consume_memleak_events()?;
            print!("{}", self.memleak_state);
        }
        if self.opts.cudatrace {
            self.consume_cudatrace_events()?;
            println!(
                "total kernel launches: {}",
                self.cudatrace_state.total_kernel_launches
            );

            for (pid, b_tree_map) in self.cudatrace_state.kernel_freq_hist.iter() {
                println!("pid: {pid}");
                for (addr, count) in b_tree_map.iter() {
                    let resolved = match self
                        .glob_process_table
                        .resolve_symbol_text_offset(*pid, *addr)
                    {
                        None => "unknown kernel".to_string(),
                        Some(str) => str,
                    };
                    let formatted = format!("0x{:x} ({})", addr, resolved);
                    println!("\t{:30} -> {}", formatted, count);
                }
            }
        }
        if self.opts.memleak || self.opts.cudatrace {
            println!("\n{}", self.err_state);
        }

        if self.opts.bandwidth_util {
            let bandwidth_util_data = self.collect_data_bandwidth_util()?;
            println!("{}", bandwidth_util_data);
        }

        println!("========================");

        // !!TODO update bandwidth statistics as well
        Ok(())
    }

    /// Attaches relevant uprobes as defined in `opts`.
    /// # Example:
    /// ```rust
    /// let opts = Opts {
    ///     memleak: true,
    ///     cudatrace: false,
    ///     bandwidth_util: true,
    /// }
    ///
    /// // attaches memleak and bandwidth util uprobes and uretprobes
    /// gpuprobe.attach_uprobes_from_opts(&opts).unwrap();
    ///
    /// ```
    pub fn attach_uprobes(&mut self) -> Result<(), GpuprobeError> {
        if self.opts.memleak {
            self.attach_memleak_uprobes()?;
        }
        if self.opts.cudatrace {
            self.attach_cudatrace_uprobes()?;
        }
        if self.opts.bandwidth_util {
            self.attach_bandwidth_util_uprobes()?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum GpuprobeError {
    OpenError,
    LoadError,
    AttachError,
    RuntimeError(String),
}

impl std::fmt::Display for GpuprobeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuprobeError::OpenError => write!(f, "failed to open skeleton"),
            GpuprobeError::LoadError => write!(f, "failed to load skeleton"),
            GpuprobeError::AttachError => write!(f, "failed to attach skeleton"),
            GpuprobeError::RuntimeError(reason) => write!(f, "runtime error: {}", reason),
        }
    }
}
