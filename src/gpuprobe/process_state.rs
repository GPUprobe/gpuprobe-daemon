use std::collections::HashMap;

use super::GpuprobeError;
use goblin::Object;
use proc_maps::get_process_maps;

pub struct GlobalProcessTable {
    per_process_tables: HashMap<u32, Option<ProcessState>>,
}

impl GlobalProcessTable {
    /// Returns a new GlobalProcessTable
    pub fn new() -> Self {
        return GlobalProcessTable {
            per_process_tables: HashMap::new(),
        };
    }

    /// Creates an entry in the per-process symbols table if it doesn't yet
    /// exist. If an entry already exists, simply returns.
    /// Since the data inside of `/proc/{pid}/exe` is static, and reading the
    /// file is relatively expensive, we enforce that it is only done once
    /// per process.
    pub fn create_entry(&mut self, pid: u32) -> Result<(), GpuprobeError> {
        if self.per_process_tables.contains_key(&pid) {
            return Ok(());
        }

        let new_entry = match ProcessState::new(pid) {
            Ok(entry) => Some(entry),
            Err(_) => None,
        };
        self.per_process_tables.insert(pid, new_entry);
        Ok(())
    }

    /// Removes the entry for pid in the per-process symbols table.
    pub fn remove_entry(&mut self, pid: u32) {
        self.per_process_tables.remove(&pid);
    }

    /// Resolves the symbol of an offset within the .text section of the
    /// binary executed by this process. Returns None if out of bounds, or
    /// doesn't point to a valid symbol
    pub fn resolve_symbol_text_offset(&self, pid: u32, virtual_offset: u64) -> Option<String> {
        let proc_state = match self.per_process_tables.get(&pid) {
            Some(ps) => ps,
            None => {
                return None;
            }
        };
        match proc_state {
            Some(proc_state) => proc_state.resolve_symbol_text_offset(virtual_offset),
            None => None,
        }
    }
}

impl std::fmt::Display for GlobalProcessTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (_, table) in self.per_process_tables.iter() {
            match table {
                Some(table) => write!(f, "{table}")?,
                None => write!(f, "NO PROCESS TABLE")?,
            }
        }
        Ok(())
    }
}

/// ProcessState wraps the virtual base address (after address-space layout
/// randomization) and elf-symbol table. We want to enable fast lookups to the
/// symbol table of a process in order to resolve CUDA kernel addresses to
/// a more human-readable name.
/// Creating a new ProcessState likely incurs some overhead as it involves
/// reading from the `/proc` pseudo-filesystem. Since this data is static, the
/// caller should only be create at most one ProcessState per process.
pub struct ProcessState {
    pid: u32,
    base_addr: u64,
    elf_symbol_table: HashMap<u64, String>,
}

impl ProcessState {
    pub fn new(pid: u32) -> Result<Self, GpuprobeError> {
        let bin_path = match std::fs::read_link(format!("/proc/{}/exe", pid)) {
            Ok(p) => p,
            Err(e) => return Err(GpuprobeError::RuntimeError(format!("{e:?}"))),
        };

        let maps = match get_process_maps(pid as i32) {
            Ok(m) => m,
            Err(e) => return Err(GpuprobeError::RuntimeError(format!("{e:?}"))),
        };

        let base = match maps
            .into_iter()
            .find(|m| m.filename().map_or(false, |f| f == bin_path))
            .map(|m| m.start())
        {
            Some(base) => base,
            None => {
                return Err(GpuprobeError::RuntimeError(
                    "unable to find binary base".to_string(),
                ));
            }
        } as u64;

        let buff =
            std::fs::read(bin_path).map_err(|e| GpuprobeError::RuntimeError(format!("{e:?}")))?;
        let obj =
            Object::parse(&buff).map_err(|e| GpuprobeError::RuntimeError(format!("{e:?}")))?;

        let symbols: HashMap<u64, String> = if let Object::Elf(elf) = obj {
            let syms = elf
                .syms
                .iter()
                .filter_map(|sym| {
                    let name = elf.strtab.get_at(sym.st_name).unwrap_or("UNDEFINED");
                    Some((sym.st_value, name.to_string()))
                })
                .collect();
            syms
        } else {
            return Err(GpuprobeError::RuntimeError(format!(
                "no `/proc` entry for pid: {pid}"
            )));
        };

        Ok(ProcessState {
            pid,
            base_addr: base,
            elf_symbol_table: symbols,
        })
    }

    /// Resolves the symbol of an offset within the .text section of the
    /// binary executed by this process. Returns None if out of bounds, or
    /// doesn't point to a valid symbol
    pub fn resolve_symbol_text_offset(&self, virtual_offset: u64) -> Option<String> {
        self.elf_symbol_table
            .get(&(virtual_offset - self.base_addr))
            .cloned()
    }
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "process {}, with base {:x}", self.pid, self.base_addr)?;
        for (addr, symbol) in self.elf_symbol_table.iter() {
            writeln!(f, "\t{:016x} -> {}", addr, symbol)?;
        }
        Ok(())
    }
}
