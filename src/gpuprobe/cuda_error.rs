use std::collections::HashMap;

use super::GpuprobeError;

/// Defines a subset of the enum values `enum cudaError_t` found in
/// driver_types.h
#[repr(i32)]
#[derive(std::cmp::PartialEq, std::cmp::Eq, std::hash::Hash, Clone, Copy, Debug)]
pub enum CudaErrorT {
    CudaSuccess,
    CudaErrorInvalidValue,
    CudaErrorMemoryAllocation,
    UnsupportedErrorType,
}

impl CudaErrorT {
    pub fn from_int(value: i32) -> Self {
        match value {
            0 => CudaErrorT::CudaSuccess,
            1 => CudaErrorT::CudaErrorInvalidValue,
            2 => CudaErrorT::CudaErrorMemoryAllocation,
            _ => CudaErrorT::UnsupportedErrorType,
        }
    }
}

#[derive(std::cmp::PartialEq, std::cmp::Eq, std::hash::Hash, Clone, Copy, Debug)]
pub enum EventType {
    CudaMalloc,
    CudaFree,
}

impl ToString for EventType {
    fn to_string(&self) -> String {
        match self {
            Self::CudaMalloc => "cudaMalloc",
            Self::CudaFree => "cudaFree",
        }
        .to_string()
    }
}

pub struct CudaError {
    pub pid: u32,
    pub event: EventType,
    pub error: CudaErrorT,
}

/// Maintains per-process error histograms
pub struct CudaErrorState {
    pub error_histogram: HashMap<u32, HashMap<(EventType, CudaErrorT), u64>>,
}

impl CudaErrorState {
    pub fn new() -> Self {
        CudaErrorState {
            error_histogram: HashMap::new(),
        }
    }

    pub fn insert(&mut self, err: CudaError) -> Result<(), GpuprobeError> {
        if !self.error_histogram.contains_key(&err.pid) {
            self.error_histogram.insert(err.pid, HashMap::new());
        }

        let hist = match self.error_histogram.get_mut(&err.pid) {
            Some(hist) => hist,
            None => panic!("no entry for {} in histogram", err.pid),
        };

        let count_ref = match hist.get_mut(&(err.event, err.error)) {
            Some(r) => r,
            None => {
                hist.insert((err.event, err.error), 1);
                return Ok(());
            }
        };
        *count_ref += 1;
        Ok(())
    }
}

impl std::fmt::Display for CudaErrorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "per-process error histograms:")?;
        for (pid, hash_map) in self.error_histogram.iter() {
            writeln!(f, "process {}", pid)?;
            for ((event, error), count) in hash_map {
                writeln!(f, "\t({}[{:?}]): {}", event.to_string(), error, count)?;
            }
        }

        Ok(())
    }
}
