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
pub struct ErrorLabelSet {
    pub pid: u32,
    pub call_type: String,
    pub return_code: u32,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct MemleakLabelSet {
    pub pid: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CudatraceLabelSet {
    pub pid: u32,
    pub kernel_offset: u64,
    pub kernel_symbol: String,
}

#[derive(Debug, Clone)]
pub struct GpuprobeMetrics {
    opts: Opts,
    pub err_hist: Family<ErrorLabelSet, Gauge>,
    // memleak metrics
    pub memleaks: Family<MemleakLabelSet, Gauge>,
    // cuda trace
    pub kernel_launches: Family<CudatraceLabelSet, Gauge>,
}

impl GpuprobeMetrics {
    pub fn new(opts: Opts) -> Result<Self, GpuprobeError> {
        Ok(GpuprobeMetrics {
            opts,
            err_hist: Family::default(),
            memleaks: Family::default(),
            kernel_launches: Family::default(),
        })
    }

    pub fn register(&self, registry: &mut Registry) {
        if self.opts.memleak {
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
        if self.opts.memleak || self.opts.cudatrace {
            registry.register(
                "cuda_error_histogram",
                "CUDA errors histogram keyed on process, error type and erroneous call",
                self.err_hist.clone(),
            )
        }
    }
}
