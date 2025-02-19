use super::{Gpuprobe, GpuprobeError};

impl Gpuprobe {
    pub fn attach_deps_tracepoints(&mut self) -> Result<(), GpuprobeError> {
        let tracepoint_enter_open = self
            .skel
            .skel
            .progs
            .tracepoint__syscalls__sys_enter_open
            .attach_tracepoint("syscalls", "sys_enter_open")
            .map_err(|_| GpuprobeError::AttachError)?;

        let tracepoint_enter_openat = self
            .skel
            .skel
            .progs
            .tracepoint__syscalls__sys_enter_openat
            .attach_tracepoint("syscalls", "sys_enter_openat")
            .map_err(|_| GpuprobeError::AttachError)?;
        
        self.links.links.tracepoint__syscalls__sys_enter_open = Some(tracepoint_enter_open);
        self.links.links.tracepoint__syscalls__sys_enter_openat = Some(tracepoint_enter_openat);
        Ok(())
    }
}
