use super::{GpuprobeError, Opts};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AddrLabel {
    pub addr: u64,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct MemleakLabelSet {
    pub pid: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct GpuprobeMetrics {
    opts: Opts,
    // memleak metrics
    pub num_mallocs: Gauge,
    pub memleaks: Family<MemleakLabelSet, Gauge>,
    // cuda trace
    pub kernel_launches: Family<AddrLabel, Gauge>,
}

impl GpuprobeMetrics {
    pub fn new(opts: Opts) -> Result<Self, GpuprobeError> {
        Ok(GpuprobeMetrics {
            opts,
            num_mallocs: Gauge::default(),
            memleaks: Family::default(),
            kernel_launches: Family::default(),
        })
    }

    pub fn register(&self, registry: &mut Registry) {
        if self.opts.memleak {
            registry.register(
                "total_cuda_mallocs",
                "Total number of cudaMalloc calls",
                self.num_mallocs.clone(),
            );
            registry.register(
                "cuda_memory_leaks",
                "Cuda memory leak statistics",
                self.memleaks.clone(),
            );
        }
        if self.opts.cudatrace {
            registry.register(
                "cuda_kernel_launches",
                "Cuda kernel launch statistics",
                self.kernel_launches.clone(),
            );
        }
    }
}
