mod gpuprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/gpuprobe.skel.rs"
    ));
}

use libbpf_rs::MapCore;

use super::uprobe_data::BandwidthUtilData;
use super::{Gpuprobe, GpuprobeError, LIBCUDART_PATH};

impl Gpuprobe {
    /// attaches uprobes for the bandwidth util program, or returns an error on
    /// failure
    pub fn attach_bandwidth_util_uprobes(&mut self) -> Result<(), GpuprobeError> {
        let cuda_memcpy_uprobe_link = self
            .skel
            .skel
            .progs
            .trace_cuda_memcpy
            .attach_uprobe(false, -1, LIBCUDART_PATH, 0x000000000006f150)
            .map_err(|_| GpuprobeError::AttachError)?;

        let cuda_memcpy_uretprobe_link = self
            .skel
            .skel
            .progs
            .trace_cuda_memcpy_ret
            .attach_uprobe(true, -1, LIBCUDART_PATH, 0x000000000006f150)
            .map_err(|_| GpuprobeError::AttachError)?;

        self.links.links.trace_cuda_memcpy = Some(cuda_memcpy_uprobe_link);
        self.links.links.trace_cuda_memcpy_ret = Some(cuda_memcpy_uretprobe_link);
        Ok(())
    }

    /// Copies all cudaMemcpy calls out of the queue and returns them as a Vec,
    /// or returns a GpuProbeError on failure
    pub fn collect_data_bandwidth_util(&self) -> Result<BandwidthUtilData, GpuprobeError> {
        let mut output: Vec<CudaMemcpy> = Vec::new();
        let key: [u8; 0] = []; // key size must be zero for BPF_MAP_TYPE_QUEUE
                               // `lookup_and_delete` calls.

        while let Ok(opt) = self
            .skel
            .skel
            .maps
            .successful_cuda_memcpy_q
            .lookup_and_delete(&key)
        {
            match opt {
                Some(bytes) => match CudaMemcpy::from_bytes(&bytes) {
                    Some(valid_instance) => output.push(valid_instance),
                    None => {
                        return Err(GpuprobeError::RuntimeError(
                            "alloc conversion failure".to_string(),
                        ))
                    }
                },
                None => {
                    // This case suggests that a queue entry has no data. If
                    // this occurs, it indicates a problem with the eBPF
                    // program, so we return a runtime error.
                    return Err(GpuprobeError::RuntimeError(
                        "Found None data for key during lookup".to_string(),
                    ));
                }
            }
        }

        Ok(BandwidthUtilData {
            cuda_memcpys: output,
        })
    }
}

pub struct CudaMemcpy {
    pub start_time: u64,
    pub end_time: u64,
    pub dst: u64,
    pub src: u64,
    pub count: u64,
    pub memcpy_kind: u32,
}

impl CudaMemcpy {
    /// Constructs a CudaMemcpy struct from a raw byte array and returns it, or
    /// None if the byte array is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }
        // This is safe if:
        // 1. The byte array contains valid data for this struct
        // 2. The byte array is at least as large as the struct
        unsafe { Some(std::ptr::read_unaligned(bytes.as_ptr() as *const Self)) }
    }

    /// Returns a human readable version of the `kind` parameter passed to
    /// `cudaMemcpy`
    pub fn kind_to_str(&self) -> String {
        match self.memcpy_kind {
            0 => "H2H".to_string(),
            1 => "H2D".to_string(),
            2 => "D2H".to_string(),
            3 => "D2D".to_string(),
            4 => "DEF".to_string(),
            _ => "INVALID KIND".to_string(),
        }
    }

    pub fn compute_bandwidth_util(&self) -> Option<f64> {
        if self.start_time >= self.end_time {
            return None;
        }

        let delta = (self.end_time - self.start_time) as f64;
        let nanos_per_second = 1e9;
        let res = (self.count as f64) / delta * nanos_per_second;
        Some(res)
    }
}

impl std::fmt::Display for CudaMemcpy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(f, "\tstart_time: {}", self.start_time)?;
        writeln!(f, "\tend_time: {}", self.end_time)?;
        writeln!(f, "\tdst: {:x}", self.dst)?;
        writeln!(f, "\tsrc: {:x}", self.dst)?;
        writeln!(f, "\tcount: {}", self.count)?;
        writeln!(f, "\tkind: {}", self.memcpy_kind)?;
        writeln!(f, "}}")
    }
}
