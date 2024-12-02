use super::gpuprobe_bandwidth_util::CudaMemcpy;

/// defines the data that is collected in a cycle of the cudatrace program
pub struct CudaTraceData {
    /// a Vec of `(addr, count)` where:
    ///     - `addr` is the function pointer to the launched cuda kernel
    ///     - `count` is the number of times that that kernel was launched
    pub kernel_frequencies_histogram: Vec<(u64, u64)>,
}

/// defines the data that is collected in a cycle of the cudatrace program
pub struct BandwidthUtilData {
    /// a Vec of `CudaMemcpy` calls
    pub cuda_memcpys: Vec<CudaMemcpy>,
}

impl std::fmt::Display for CudaTraceData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kernel_launches = &self.kernel_frequencies_histogram;
        let num_launches = kernel_launches
            .iter()
            .fold(0u64, |total, (_, count)| total + count);

        writeln!(
            f,
            "{} `cudaLaunchKernel` calls for {} kernels",
            num_launches,
            kernel_launches.len()
        )?;

        for (addr, count) in kernel_launches.iter() {
            writeln!(f, "\t0x{addr:x}: {count} launches")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for BandwidthUtilData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let calls = &self.cuda_memcpys;
        if calls.len() == 0 {
            return Ok(());
        }

        writeln!(f, "Traced {} cudaMemcpy calls", calls.len())?;
        for c in calls.iter() {
            let bandwidth_util = c.compute_bandwidth_util().unwrap_or(0.0);
            let delta = (c.end_time - c.start_time) as f64 / 1e9;
            writeln!(
                f,
                "\t{} {:.5} bytes/sec for {:.5} secs",
                c.kind_to_str(),
                bandwidth_util,
                delta
            )?;
        }
        Ok(())
    }
}
