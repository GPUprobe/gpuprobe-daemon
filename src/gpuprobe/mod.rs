pub mod gpuprobe_bandwidth_util;
pub mod gpuprobe_cudatrace;
pub mod gpuprobe_memleak;
pub mod metrics;
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

use self::gpuprobe_memleak::MemleakState;
use self::metrics::AddrLabel;

const LIBCUDART_PATH: &str = "/usr/local/cuda/lib64/libcudart.so";

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
/// !!TODO!! maybe consider using orobouros self-referential instead of the
/// static lifetime
pub struct Gpuprobe {
    obj: SafeGpuProbeObj,
    skel: SafeGpuprobeSkel, // references a static lifetime! See struct def
    links: SafeGpuprobeLinks,
    opts: Opts,
    pub metrics: GpuprobeMetrics,
    memleak_state: MemleakState,
}

#[derive(Clone, Debug)]
pub struct Opts {
    pub memleak: bool,
    pub cudatrace: bool,
    pub bandwidth_util: bool,
}

const DEFAULT_LINKS: GpuprobeLinks = GpuprobeLinks {
    memleak_cuda_malloc: None,
    memleak_cuda_malloc_ret: None,
    trace_cuda_free: None,
    trace_cuda_free_ret: None,
    trace_cuda_launch_kernel: None,
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
        })
    }

    /// Updates prometheus metrics registered by the GPUprobe instance
    pub fn export_open_metrics(&mut self) -> Result<(), GpuprobeError> {
        // updates memory leak stats
        if self.opts.memleak {
            // todo GC cycle for cleaning up memory maps??
            self.memleak_state.cleanup_terminated_processes()?;
            self.consume_memleak_events()?;

            self.metrics
                .num_mallocs
                .set(self.memleak_state.num_successful_mallocs as i64);

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
            //for (addr, count) in memleak_state.outstanding_allocs {
            //    self.metrics
            //        .memleaks
            //        .get_or_create(&AddrLabel { addr })
            //        .set(count as i64);
            //}
        }
        // updates kernel launch stats
        if self.opts.cudatrace {
            let cudatrace_data = self.collect_data_cudatrace()?;
            for (addr, count) in cudatrace_data.kernel_frequencies_histogram {
                self.metrics
                    .kernel_launches
                    .get_or_create(&AddrLabel { addr })
                    .set(count as i64);
            }
        }

        // !!TODO update bandwidth statistics as well
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
            let cudatrace_data = self.collect_data_cudatrace()?;
            println!("{}", cudatrace_data);
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
