// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use core::panic;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::process;
use std::sync::MutexGuard;
use std::time::Instant;

use super::executor_bool;
use super::executor_callother;
use super::executor_float;
use super::executor_int;
use super::ConcolicEnum;
pub use super::ConcreteVar;
pub use super::SymbolicVar;
use crate::concolic::ConcolicVar;
use crate::state::cpu_state::CpuConcolicValue;
use crate::state::evaluate_args_z3;
#[allow(unused_imports)]
use crate::state::memory_x86_64::MemoryError;
use crate::state::memory_x86_64::MemoryValue;
use crate::state::simplify_z3::extract_underlying_condition_from_flag_ast;
use crate::state::state_manager::FunctionFrame;
use crate::state::state_manager::Logger;
use crate::state::CpuState;
use crate::state::State;
use goblin::elf::Elf;
use parser::parser::{Inst, Opcode, Var, Varnode};
use z3::ast::Ast;
use z3::ast::Bool;
use z3::ast::BV;
use z3::{Context, Optimize};

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
            writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

#[derive(Debug)]
pub struct ConcolicExecutor<'ctx> {
    pub context: &'ctx Context,
    pub solver: Optimize<'ctx>, // Use Optimize instead of Solver to get symbolic variables minimization
    pub state: State<'ctx>,
    pub current_address: Option<u64>,
    pub symbol_table: BTreeMap<String, String>,
    pub instruction_counter: usize,
    pub unique_variables: BTreeMap<String, ConcolicVar<'ctx>>, // Stores unique variables and their values
    pub pcode_internal_lines_to_be_jumped: i64, // known line number of the current instruction in the pcode file, usefull for branch instructions
    pub initialiazed_var: BTreeMap<u64, u64>, // check if the variable has been initialized before using it
    pub inside_jump_table: bool, // check if the current instruction is handling a jump table
    pub trace_logger: Logger,
    pub function_symbolic_arguments: BTreeMap<String, SymbolicVar<'ctx>>, // this is used to store the symbolic arguments of the binary (os.args) or the function (RSI, RDX, RCX, R8, R9 etc.)
    pub constraint_vector: Vec<Bool<'ctx>>, // Vector to collect constraints on tracked symbolic variables
    pub overlay_state: Option<crate::state::OverlayState<'ctx>>, // Overlay state for exploring untaken paths without modifying base state
    pub null_check_cache: std::collections::HashMap<String, (bool, usize)>, // Per-variable cache: maps symbolic variable name → (was_sat, constraint_len). If was_sat=true the variable is permanently skipped (vulnerability already reported). If was_sat=false it is re-checked only when constraint_len changes. For Go struct pointers this is pre-seeded with (false, 0) at initialization so the solver is never invoked.
    pub start_time: Instant, // Execution start time for elapsed time tracking
    pub visited_blocks: BTreeSet<u64>, // Tracks which basic-block addresses have been entered during execution (for block-level coverage metrics)
}

impl<'ctx> ConcolicExecutor<'ctx> {
    pub fn new(
        context: &'ctx Context,
        logger: Logger,
        trace_logger: Logger,
    ) -> Result<Self, Box<dyn Error>> {
        let solver = Optimize::new(context);
        let state = State::new(context, logger)?;
        Ok(ConcolicExecutor {
            context,
            solver,
            state,
            symbol_table: BTreeMap::new(),
            current_address: None,
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),
            pcode_internal_lines_to_be_jumped: 0, // number of lines to skip in case of branch instructions
            initialiazed_var: BTreeMap::new(),
            inside_jump_table: false,
            trace_logger,
            function_symbolic_arguments: BTreeMap::new(),
            constraint_vector: Vec::new(),
            overlay_state: None, // No overlay by default
            null_check_cache: std::collections::HashMap::new(),
            start_time: Instant::now(),
            visited_blocks: BTreeSet::new(),
        })
    }

    /// Check if overlay mode is active
    pub fn is_overlay_mode(&self) -> bool {
        self.overlay_state.is_some()
    }

    /// Get register value with overlay support
    /// If overlay mode is active, reads from overlay first, then falls back to base
    pub fn get_register_overlay_aware(
        &self,
        offset: u64,
        access_size: u32,
    ) -> Option<crate::state::cpu_state::CpuConcolicValue<'ctx>> {
        if let Some(ref overlay) = self.overlay_state {
            // Try overlay first
            if let Some(val) = overlay
                .cpu_overlay
                .get_register_by_offset(offset, access_size)
            {
                return Some(val);
            }
        }

        // Fall back to base state
        self.state
            .cpu_state
            .lock()
            .ok()
            .and_then(|cpu| cpu.get_register_by_offset(offset, access_size))
    }

    /// Set register value with overlay support
    /// If overlay mode is active, writes to overlay only
    /// Otherwise writes to base state
    pub fn set_register_overlay_aware(
        &mut self,
        offset: u64,
        value: ConcolicVar<'ctx>,
        size: u32,
    ) -> Result<(), String> {
        if let Some(ref mut overlay) = self.overlay_state {
            // Write to overlay
            overlay
                .cpu_overlay
                .set_register_value_by_offset(offset, value, size)
        } else {
            // Write to base state
            self.state
                .cpu_state
                .lock()
                .map_err(|e| format!("Failed to lock CPU state: {}", e))?
                .set_register_value_by_offset(offset, value, size)
        }
    }

    /// Extract current goroutine ID from TLS (Thread Local Storage)
    ///
    /// For Go binaries, the goroutine ID is stored in the runtime.g structure.
    /// The current g pointer is accessible via TLS:
    /// - FS register (0x110) points to TLS base
    /// - g pointer is at FS:[-8] (fs_base - 8)
    /// - goid field offset is dynamically loaded from DWARF debug info
    ///
    /// The offset varies by Go version (e.g., 152 for Go 1.25.1, 192 for Go 1.21+)
    /// and is automatically extracted during function signature analysis.
    ///
    /// This works for both Go GC and TinyGo binaries.
    pub fn get_current_goroutine_id(&self) -> Result<u64, String> {
        let source_lang = std::env::var("SOURCE_LANG").unwrap_or_default();

        // Only extract for Go binaries
        if source_lang.to_lowercase() != "go" {
            return Ok(0);
        }

        // Try to extract from TLS (works for both gc and tinygo)
        self.extract_gid_from_tls()
    }

    /// Extract goroutine ID from TLS by reading the runtime.g structure
    ///
    /// TLS access pattern:
    ///   1. Read FS register (0x110) → TLS base
    ///   2. Read g pointer at TLS base - 8
    ///   3. Read goid field at g + offset
    ///
    /// The goid offset is loaded from results/runtime_g_offsets.json,
    /// which is generated during DWARF analysis.
    fn extract_gid_from_tls(&self) -> Result<u64, String> {
        // Read FS base register (TLS base)
        let cpu_state = self
            .state
            .cpu_state
            .lock()
            .map_err(|e| format!("Failed to lock CPU state: {}", e))?;

        let fs_base = cpu_state
            .get_register_by_offset(0x110, 64) // FS_OFFSET
            .map(|v| v.concrete.to_u64())
            .unwrap_or(0);

        drop(cpu_state); // Release lock

        if fs_base == 0 {
            // TLS not set up yet, return 0 (main goroutine)
            return Ok(0);
        }

        // Read g pointer at fs_base - 8
        // In Go runtime, the current goroutine pointer is stored at FS:[-8]
        // See https://github.com/golang/go/commit/658a338f78ef5dce4c81527c34fb52be95357ef7
        let g_ptr_addr = fs_base.wrapping_sub(8);
        let g_ptr = self
            .state
            .memory
            .read_value(g_ptr_addr, 64, &mut self.state.logger.clone())
            .map(|v| v.concrete.to_u64())
            .unwrap_or(0);

        if g_ptr == 0 {
            // No goroutine context, return 0
            return Ok(0);
        }

        // Read goid field from g struct using dynamically loaded offset
        // The offset is extracted from DWARF at initialization time
        let goid_offset = crate::state::RuntimeGOffsets::get_goid_offset();
        let goid = self
            .state
            .memory
            .read_value(g_ptr + goid_offset, 64, &mut self.state.logger.clone())
            .map(|v| v.concrete.to_u64())
            .unwrap_or(0);

        Ok(goid)
    }

    /// Read memory with overlay support
    /// If overlay mode is active, reads from overlay first, then falls back to base.
    /// The symbolic component is a per-byte `Vec<Option<Rc<BV>>>` (one 8-bit BV per byte),
    /// matching the storage convention of `MemoryX86_64::read_memory`.
    pub fn read_memory_overlay_aware(
        &mut self,
        address: u64,
        size: usize,
    ) -> Result<
        crate::state::memory_x86_64::MemoryReadResult<'ctx>,
        crate::state::memory_x86_64::MemoryError,
    > {
        if let Some(ref mut overlay) = self.overlay_state {
            // Find the region containing this address
            if let Some((region_start, _)) = self.state.memory.find_region_bounds(address, size) {
                if let Some(region_ptr) = self.state.memory.get_region_ptr(region_start) {
                    // SAFETY: Region exists and won't be modified during overlay operation
                    let region = unsafe { &*region_ptr };

                    // read_memory now returns per-byte symbolic data directly — no conversion
                    // or replication needed.  Previously the single word-level BV returned here
                    // was replicated with `vec![Some(sym); size]`, which caused all byte
                    // positions to carry the byte-0 symbolic and produced the
                    // #x0808080808080808 fill-pattern on reads of base-inherited addresses.
                    if let Some((concrete, symbolic_per_byte)) =
                        overlay.read_memory(address, size, region)
                    {
                        return Ok((concrete, symbolic_per_byte));
                    }
                }
            }
        }

        // Fall back to base state
        self.state.memory.read_memory(address, size)
    }

    /// Write memory with overlay support
    /// If overlay mode is active, writes to overlay only
    /// Otherwise writes to base state
    pub fn write_memory_overlay_aware(
        &mut self,
        address: u64,
        concrete_data: &[u8],
        symbolic_data: Option<std::rc::Rc<BV<'ctx>>>,
    ) -> Result<(), String> {
        if let Some(ref mut overlay) = self.overlay_state {
            // Find the region containing this address
            let (region_start, _) = self
                .state
                .memory
                .find_region_bounds(address, concrete_data.len())
                .ok_or(format!(
                    "No memory region found for address 0x{:x}",
                    address
                ))?;

            let region_ptr = self
                .state
                .memory
                .get_region_ptr(region_start)
                .ok_or(format!(
                    "Failed to get region pointer for address 0x{:x}",
                    region_start
                ))?;

            // SAFETY: Region exists and won't be modified during overlay operation
            let region = unsafe { &*region_ptr };

            // Write to overlay
            overlay.write_memory(address, concrete_data, symbolic_data, region)
        } else {
            // Write to base state
            let symbolic_vec: Vec<Option<std::rc::Rc<BV<'ctx>>>> = if let Some(sym) = symbolic_data
            {
                vec![Some(sym); concrete_data.len()]
            } else {
                vec![None; concrete_data.len()]
            };
            self.state
                .memory
                .write_memory(address, concrete_data, &symbolic_vec)
                .map_err(|e| format!("Failed to write memory: {:?}", e))
        }
    }

    /// Read a value from memory in overlay mode
    /// This is a helper that mimics the behavior of MemoryX86_64::read_value but uses overlay
    fn read_value_overlay_mode(
        &mut self,
        address: u64,
        size_bits: u32,
    ) -> Result<ConcolicVar<'ctx>, String> {
        let byte_size = size_bits.div_ceil(8) as usize;

        // Use overlay-aware memory reading
        let (concrete_bytes, symbolic_vec) = self
            .read_memory_overlay_aware(address, byte_size)
            .map_err(|e| format!("Failed to read from overlay at 0x{:x}: {:?}", address, e))?;

        // Convert bytes to u64
        let mut padded = vec![0u8; 8.max(byte_size)];
        padded[..concrete_bytes.len()].copy_from_slice(&concrete_bytes);
        let value = u64::from_le_bytes(padded[..8].try_into().unwrap());

        // Apply mask for the requested size
        let mask = if size_bits < 64 {
            (1u64 << size_bits) - 1
        } else {
            u64::MAX
        };
        let masked = value & mask;

        // Build symbolic value - check if any bytes have symbolic data
        let has_symbolic = symbolic_vec.iter().any(|opt| opt.is_some());

        let symbolic_bv = if has_symbolic {
            // Concatenate symbolic bytes (similar to MemoryX86_64::concatenate_symbolic_bytes)
            let mut result: Option<BV<'ctx>> = None;
            for (sym_opt, &concrete_byte) in symbolic_vec.iter().zip(concrete_bytes.iter()).rev() {
                let byte_bv = if let Some(sym_ref) = sym_opt {
                    sym_ref.as_ref().clone()
                } else {
                    BV::from_u64(self.context, concrete_byte as u64, 8)
                };

                result = Some(if let Some(acc) = result {
                    byte_bv.concat(&acc)
                } else {
                    byte_bv
                });
            }
            result.unwrap_or_else(|| BV::from_u64(self.context, masked, size_bits))
        } else {
            BV::from_u64(self.context, masked, size_bits)
        };

        // Resize if needed
        let resized_sym = if symbolic_bv.get_size() < size_bits {
            symbolic_bv.zero_ext(size_bits - symbolic_bv.get_size())
        } else if symbolic_bv.get_size() > size_bits {
            symbolic_bv.extract(size_bits - 1, 0)
        } else {
            symbolic_bv
        };

        Ok(ConcolicVar {
            concrete: ConcreteVar::Int(masked),
            symbolic: SymbolicVar::Int(resized_sym),
            ctx: self.context,
        })
    }

    /// Write a value to memory in overlay mode
    /// This is a helper that mimics the behavior of MemoryX86_64::write_value but uses overlay
    fn write_value_overlay_mode(
        &mut self,
        address: u64,
        mem_value: &MemoryValue<'ctx>,
    ) -> Result<(), crate::state::memory_x86_64::MemoryError> {
        let size_bits = mem_value.size;
        let byte_size = size_bits.div_ceil(8) as usize;

        // Convert concrete value to bytes
        let concrete_bytes = mem_value.concrete.to_le_bytes()[..byte_size].to_vec();

        let symbolic_arc = Some(std::rc::Rc::new(mem_value.symbolic.clone()));

        // Use overlay-aware memory writing
        self.write_memory_overlay_aware(address, &concrete_bytes, symbolic_arc)
            .map_err(|_| crate::state::memory_x86_64::MemoryError::WriteOutOfBounds)
    }

    pub fn populate_symbol_table(&mut self, elf_data: &[u8]) -> Result<(), goblin::error::Error> {
        let elf = Elf::parse(elf_data)?;

        // Populate static function symbols from the symbol table
        for sym in &elf.syms {
            if goblin::elf::sym::st_type(sym.st_info) == goblin::elf::sym::STT_FUNC {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    let address_hex = format!("{:x}", sym.st_value);
                    self.symbol_table.insert(address_hex, name.to_string());
                }
            }
        }

        // Populate dynamic function symbols from the dynamic symbol table
        for dynsym in &elf.dynsyms {
            if goblin::elf::sym::st_type(dynsym.st_info) == goblin::elf::sym::STT_FUNC {
                if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
                    let address_hex = format!("{:x}", dynsym.st_value);
                    self.symbol_table.insert(address_hex, name.to_string());
                }
            }
        }

        // Resolve .plt section entries if present
        if let Some(plt_section) = elf.section_headers.iter().find(|section| {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                name == ".plt"
            } else {
                false
            }
        }) {
            let plt_start = plt_section.sh_addr;
            let plt_size = plt_section.sh_size;
            let plt_end = plt_start + plt_size;

            // Process each address in .plt section
            for addr in (plt_start..plt_end).step_by(16) {
                // Check if this address is already resolved
                if let Some(_symbol_name) = self.symbol_table.get(&format!("{:x}", addr)) {
                    continue; // Skip if already resolved
                }

                // Try resolving via GOT
                if let Some(external_name) = self.resolve_got_function(&elf, addr) {
                    self.symbol_table
                        .insert(format!("{:x}", addr), format!("plt_{}", external_name));
                } else {
                    // Fallback to synthetic naming if unresolved
                    self.symbol_table
                        .insert(format!("{:x}", addr), format!("plt_function_{:x}", addr));
                }
            }
        }

        Ok(())
    }

    // Find the enclosing function symbol name for an address using the existing hex-keyed table
    pub fn enclosing_symbol_name(&self, addr: u64) -> Option<String> {
        let mut best: Option<(u64, &String)> = None;
        for (hex, name) in &self.symbol_table {
            if let Ok(sym_addr) = u64::from_str_radix(hex, 16) {
                if sym_addr <= addr {
                    match best {
                        None => best = Some((sym_addr, name)),
                        Some((cur, _)) if sym_addr > cur => best = Some((sym_addr, name)),
                        _ => {}
                    }
                }
            }
        }
        best.map(|(_, n)| n.clone())
    }

    // Helper function to resolve function names via GOT
    fn resolve_got_function(&mut self, elf: &Elf, plt_addr: u64) -> Option<String> {
        // Look for GOT entries that are referenced by the dynamic symbol table
        for dynsym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
                if dynsym.st_value == plt_addr {
                    return Some(name.to_string());
                }
            }
        }

        // If no direct match is found, attempt to find corresponding GOT address
        if let Some(got_section) = elf.section_headers.iter().find(|section| {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                name == ".got.plt" || name == ".got"
            } else {
                false
            }
        }) {
            let got_start = got_section.sh_addr;
            let got_end = got_start + got_section.sh_size;

            for addr in (got_start..got_end).step_by(8) {
                if addr == plt_addr {
                    // Attempt to match the GOT entry with a dynamic symbol
                    for dynsym in &elf.dynsyms {
                        if dynsym.st_value == addr {
                            if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
                                return Some(name.to_string());
                            }
                        }
                    }
                }
            }
        }

        None // Could not resolve
    }

    pub fn execute_instruction(
        &mut self,
        instruction: Inst,
        current_addr: u64,
        next_addr_in_map: u64,
        instructions_map: &BTreeMap<u64, Vec<Inst>>,
    ) -> Result<(), String> {
        // Convert current_addr to hexadecimal string to match with symbol table keys
        let current_addr_hex = format!("{:x}", current_addr);

        // Check if we are processing a new address block
        if Some(current_addr) != self.current_address {
            // Reset the unique variables for the new address
            self.unique_variables.clear();

            // Update the current address
            self.current_address = Some(current_addr);
            // Reset the instruction counter for the new address
            self.instruction_counter = 1; // Start counting from 1 for each address block

            // Check if the current address corresponds to a runtime panic function
            if let Some(symbol_name) = self.symbol_table.get(&current_addr_hex).cloned() {
                if symbol_name == "runtime.nilPanic" {
                    // Log all the constraints accumulated in the solver until that point
                    evaluate_args_z3(
                        self,
                        &instruction,
                        None,
                        Some(current_addr),
                        None,
                        None, // No panic addr for non-CBranch instructions
                        None, // No NULL check for panic functions
                    )
                    .map_err(|e| e.to_string())?;
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut self.state.logger.clone(),
                        "Go runtime.nilPanic — nil pointer dereference",
                        current_addr,
                        &[
                            "Detection method: Exploring the not taken path and Reaching a Panic/Abort/Fatal call site",
                            "You are trying to dereference a nil pointer.",
                        ],
                    );
                    process::exit(0);
                }
                if symbol_name == "runtime.nilMapPanic" {
                    // Log all the constraints accumulated in the solver until that point
                    evaluate_args_z3(
                        self,
                        &instruction,
                        None,
                        Some(current_addr),
                        None,
                        None, // No panic addr for non-CBranch instructions
                        None, // No NULL check for panic functions
                    )
                    .map_err(|e| e.to_string())?;
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut self.state.logger.clone(),
                        "Go runtime.nilMapPanic — nil map access",
                        current_addr,
                        &[
                            "Detection method: Exploring the not taken path and Reaching a Panic/Abort/Fatal call site",
                            "You are trying to add an entry to a nil map.",
                        ],
                    );
                    process::exit(0);
                }
                if symbol_name == "runtime._panic" {
                    // Log all the constraints accumulated in the solver until that point
                    evaluate_args_z3(
                        self,
                        &instruction,
                        None,
                        Some(current_addr),
                        None,
                        None, // No panic addr for non-CBranch instructions
                        None, // No NULL check for panic functions
                    )
                    .map_err(|e| e.to_string())?;
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut self.state.logger.clone(),
                        "Go runtime._panic — generic panic",
                        current_addr,
                        &[
                            "Detection method: Exploring the not taken path and Reaching a Panic/Abort/Fatal call site",
                            "The Go runtime triggered a generic panic.",
                        ],
                    );
                    process::exit(0);
                }
                if symbol_name == "runtime.recordForPanic" {
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut self.state.logger.clone(),
                        "Go runtime.recordForPanic (may not be a real panic)",
                        current_addr,
                        &[
                            "Detection method: Exploring the not taken path and Reaching a Panic/Abort/Fatal call site",
                            "Encountered runtime.recordForPanic — this may be benign.",
                        ],
                    );
                    // process::exit(0);
                }
                if symbol_name == "runtime.slicePanic" {
                    // Log all the constraints accumulated in the solver until that point
                    evaluate_args_z3(
                        self,
                        &instruction,
                        None,
                        Some(current_addr),
                        None,
                        None, // No panic addr for non-CBranch instructions
                        None, // No NULL check for panic functions
                    )
                    .map_err(|e| e.to_string())?;
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut self.state.logger.clone(),
                        "Go runtime.slicePanic — slice bounds out of range",
                        current_addr,
                        &[
                            "Detection method: Exploring the not taken path and Reaching a Panic/Abort/Fatal call site",
                            "Slice index is out of bounds.",
                        ],
                    );
                    process::exit(0);
                }
                if symbol_name == "runtime.lookupPanic" {
                    // Log all the constraints accumulated in the solver until that point
                    evaluate_args_z3(
                        self,
                        &instruction,
                        None,
                        Some(current_addr),
                        None,
                        None, // No panic addr for non-CBranch instructions
                        None, // No NULL check for panic functions
                    )
                    .map_err(|e| e.to_string())?;
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut self.state.logger.clone(),
                        "Go runtime.lookupPanic — index out of bounds",
                        current_addr,
                        &[
                            "Detection method: Exploring the not taken path and Reaching a Panic/Abort/Fatal call site",
                            "You are trying to access an array or slice out of bounds.",
                        ],
                    );
                    process::exit(0);
                }
                if symbol_name == "runtime.runtimePanic" {
                    // Log all the constraints accumulated in the solver until that point
                    evaluate_args_z3(
                        self,
                        &instruction,
                        None,
                        Some(current_addr),
                        None,
                        None, // No panic addr for non-CBranch instructions
                        None, // No NULL check for panic functions
                    )
                    .map_err(|e| e.to_string())?;
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut self.state.logger.clone(),
                        "Go runtime.runtimePanic — generic runtime panic",
                        current_addr,
                        &[
                            "Detection method: Exploring the not taken path and Reaching a Panic/Abort/Fatal call site",
                            "The Go runtime triggered a generic runtime panic.",
                        ],
                    );
                    process::exit(0);
                }
                if symbol_name == "runtime.chanMakePanic" {
                    // Log all the constraints accumulated in the solver until that point
                    evaluate_args_z3(
                        self,
                        &instruction,
                        None,
                        Some(current_addr),
                        None,
                        None, // No panic addr for non-CBranch instructions
                        None, // No NULL check for panic functions
                    )
                    .map_err(|e| e.to_string())?;
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut self.state.logger.clone(),
                        "Go runtime.chanMakePanic — channel creation error",
                        current_addr,
                        &[
                            "Detection method: Exploring the not taken path and Reaching a Panic/Abort/Fatal call site",
                            "You are trying to create a new channel that is too big.",
                        ],
                    );
                    process::exit(0);
                }
                if symbol_name == "runtime.negativeShiftPanic" {
                    // Log all the constraints accumulated in the solver until that point
                    evaluate_args_z3(
                        self,
                        &instruction,
                        None,
                        Some(current_addr),
                        None,
                        None, // No panic addr for non-CBranch instructions
                        None, // No NULL check for panic functions
                    )
                    .map_err(|e| e.to_string())?;
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut self.state.logger.clone(),
                        "Go runtime.negativeShiftPanic — negative shift",
                        current_addr,
                        &[
                            "Detection method: Exploring the not taken path and Reaching a Panic/Abort/Fatal call site",
                            "The shift value is negative.",
                        ],
                    );
                    process::exit(0);
                }
            }
        } else {
            // Same address block, increment the instruction counter
            self.instruction_counter += 1;
        }

        match instruction.opcode {
            Opcode::Blank => panic!("Opcode Blank is not implemented yet"),
            Opcode::Branch => self.handle_branch(instruction), // unconditional jump to a specified address
            Opcode::BranchInd => self.handle_branchind(instruction),
            Opcode::Build => panic!("Opcode Build is not implemented yet"),
            Opcode::Call => self.handle_call(instruction), // function call, semantically similar to a branch but represents execution flow transferring to a subroutine
            Opcode::CallInd => self.handle_callind(instruction), // indirect call to a dynamically determined address
            Opcode::Ceil => panic!("Opcode Ceil is not implemented yet"),
            Opcode::CBranch => self.handle_cbranch(instruction, next_addr_in_map), // adds a condition to the jump
            Opcode::Copy => self.handle_copy(instruction),
            Opcode::CPoolRef => panic!("Opcode CPoolRef is not implemented yet"), // returns runtime-dependent values from the constant pool
            Opcode::CrossBuild => panic!("Opcode CrossBuild is not implemented yet"),
            Opcode::DelaySlot => panic!("Opcode DelaySlot is not implemented yet"),
            Opcode::Label => panic!("Opcode Label is not implemented yet"),
            Opcode::Load => self.handle_load(instruction, instructions_map),
            Opcode::LZCount => panic!("Opcode LZCount is not implemented yet"), //self.handle_lzcount(instruction),
            Opcode::New => panic!("Opcode New is not implemented yet"), // allocates memory for an object and returns a pointer to that memory
            Opcode::Piece => panic!("Opcode Piece is not implemented yet"), // concatenation operation that combines two inputs
            Opcode::PopCount => self.handle_popcount(instruction),
            Opcode::Return => self.handle_return(instruction), // indicates a return from a subroutine
            Opcode::Round => panic!("Opcode Round is not implemented yet"),
            Opcode::SegmentOp => panic!("Opcode SegmentOp is not implemented yet"),
            Opcode::Store => self.handle_store(instruction),
            Opcode::SubPiece => self.handle_subpiece(instruction),
            Opcode::Trunc => executor_float::handle_trunc(self, instruction),
            Opcode::Unused1 => panic!("Opcode Unused1 is not implemented yet"),

            // Check executor_bool.rs for functions' implementations
            Opcode::BoolAnd => executor_bool::handle_bool_and(self, instruction),
            Opcode::BoolNegate => executor_bool::handle_bool_negate(self, instruction),
            Opcode::BoolOr => executor_bool::handle_bool_or(self, instruction),
            Opcode::BoolXor => executor_bool::handle_bool_xor(self, instruction),

            // Check executor_callother.rs for functions' implementations
            Opcode::CallOther => executor_callother::handle_callother(self, instruction),

            // Check executor_float.rs for functions' implementations
            Opcode::Float2Float => panic!("Opcode is not implemented yet"), //executor_float::handle_float2float(self, instruction),
            Opcode::FloatAbs => panic!("Opcode is not implemented yet"), //executor_float::handle_float_abs(self, instruction),
            Opcode::FloatAdd => panic!("Opcode is not implemented yet"), //executor_float::handle_float_add(self, instruction),
            Opcode::FloatDiv => panic!("Opcode is not implemented yet"), //executor_float::handle_float_div(self, instruction),
            Opcode::FloatEqual => executor_float::handle_float_equal(self, instruction),
            Opcode::FloatLess => executor_float::handle_float_less(self, instruction),
            Opcode::FloatLessEqual => panic!("Opcode is not implemented yet"), //executor_float::handle_float_lessequal(self, instruction),
            Opcode::FloatMult => executor_float::handle_float_mult(self, instruction),
            Opcode::FloatNaN => executor_float::handle_float_nan(self, instruction),
            Opcode::FloatNeg => panic!("Opcode is not implemented yet"), //executor_float::handle_float_neg(self, instruction),
            Opcode::FloatNotEqual => panic!("Opcode is not implemented yet"), //executor_float::handle_float_notequal(self, instruction),
            Opcode::FloatSqrt => panic!("Opcode is not implemented yet"), //executor_float::handle_float_sqrt(self, instruction),
            Opcode::FloatSub => panic!("Opcode is not implemented yet"), //executor_float::handle_float_sub(self, instruction),
            Opcode::FloatFloor => panic!("Opcode is not implemented yet"), //executor_float::handle_float_floor(self, instruction),

            // Check executor_int.rs for functions' implementations
            Opcode::Int2Comp => executor_int::handle_int_2comp(self, instruction),
            Opcode::Int2Float => executor_int::handle_int2float(self, instruction),
            Opcode::IntAdd => executor_int::handle_int_add(self, instruction),
            Opcode::IntAnd => executor_int::handle_int_and(self, instruction),
            Opcode::IntCarry => executor_int::handle_int_carry(self, instruction),
            Opcode::IntDiv => executor_int::handle_int_div(self, instruction),
            Opcode::IntEqual => executor_int::handle_int_equal(self, instruction),
            Opcode::IntLeft => executor_int::handle_int_left(self, instruction),
            Opcode::IntLess => executor_int::handle_int_less(self, instruction),
            Opcode::IntLessEqual => executor_int::handle_int_lessequal(self, instruction),
            Opcode::IntMult => executor_int::handle_int_mult(self, instruction),
            Opcode::IntNegate => executor_int::handle_int_negate(self, instruction),
            Opcode::IntNotEqual => executor_int::handle_int_notequal(self, instruction),
            Opcode::IntOr => executor_int::handle_int_or(self, instruction),
            Opcode::IntRem => executor_int::handle_int_rem(self, instruction),
            Opcode::IntRight => executor_int::handle_int_right(self, instruction),
            Opcode::IntSDiv => executor_int::handle_int_sdiv(self, instruction),
            Opcode::IntSExt => executor_int::handle_int_sext(self, instruction),
            Opcode::IntSCarry => executor_int::handle_int_scarry(self, instruction),
            Opcode::IntSBorrow => executor_int::handle_int_sborrow(self, instruction),
            Opcode::IntSRem => executor_int::handle_int_srem(self, instruction),
            Opcode::IntSLess => executor_int::handle_int_sless(self, instruction),
            Opcode::IntSLessEqual => executor_int::handle_int_slessequal(self, instruction),
            Opcode::IntSRight => executor_int::handle_int_sright(self, instruction),
            Opcode::IntSub => executor_int::handle_int_sub(self, instruction),
            Opcode::IntXor => executor_int::handle_int_xor(self, instruction),
            Opcode::IntZExt => executor_int::handle_int_zext(self, instruction),
        }?;
        Ok(())
    }

    // Transform the varnode.var into a concolic object in zorya
    pub fn varnode_to_concolic(&mut self, varnode: &Varnode) -> Result<ConcolicEnum<'ctx>, String> {
        log!(
            self.state.logger.clone(),
            "Converting Varnode to concolic type: {:?}",
            varnode.var
        );

        let bit_size = varnode.size.to_bitvector_size(); // size in bits
        match &varnode.var {
            Var::Register(offset, _) => {
                log!(
                    self.state.logger.clone(),
                    "Varnode is a CPU register with offset: 0x{:x} and requested bit size: {}",
                    offset,
                    bit_size
                );

                // Check register map to see if it exists and get its size
                let (reg_exists, reg_size) = {
                    let cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    if let Some(&(ref _name, reg_size)) = cpu_state_guard.register_map.get(offset) {
                        (true, reg_size)
                    } else {
                        (false, 0)
                    }
                };

                if reg_exists {
                    if reg_size == bit_size {
                        log!(self.state.logger.clone(), "Directly processing register found in register_map with matching size at offset 0x{:x}", offset);

                        // Use overlay-aware register read (reads from overlay if active, otherwise base)
                        let cpu_concolic_value = self
                            .get_register_overlay_aware(*offset, reg_size)
                            .ok_or_else(|| {
                                format!("Failed to retrieve register by offset 0x{:x}", offset)
                            })?;
                        Ok(ConcolicEnum::CpuConcolicValue(cpu_concolic_value))
                    } else {
                        log!(self.state.logger.clone(), "Register at offset 0x{:x} exists but with size {} bits, needs {} bits, extraction needed", offset, reg_size, bit_size);

                        // Read the full register (overlay-aware), then extract the needed portion
                        let full_register = self
                            .get_register_overlay_aware(*offset, reg_size)
                            .ok_or_else(|| {
                                format!(
                                    "Failed to retrieve register for extraction at offset 0x{:x}",
                                    offset
                                )
                            })?;

                        // Extract the requested bit range from the full register
                        self.extract_from_cpu_value(&full_register, *offset, bit_size)
                    }
                } else {
                    log!(
                        self.state.logger.clone(),
                        "No direct register match found at offset 0x{:x}, extraction required",
                        offset
                    );

                    // Find containing register (overlay-aware)
                    let containing_offset = self.find_containing_register_offset(*offset);
                    if let Some(container_offset) = containing_offset {
                        if let Some(full_register) =
                            self.get_register_overlay_aware(container_offset.0, container_offset.1)
                        {
                            return self.extract_from_cpu_value(&full_register, *offset, bit_size);
                        }
                    }

                    // Fallback to base state extraction
                    let cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    self.extract_and_create_concolic_value(&cpu_state_guard, *offset, bit_size)
                }
            }
            Var::Unique(id) => {
                log!(
                    self.state.logger.clone(),
                    "Varnode is of type 'unique' with ID: 0x{:x} and size: {} bits",
                    id,
                    bit_size
                );
                let unique_name = format!("Unique(0x{:x})", id);

                let unique_var = self
                    .unique_variables
                    .entry(unique_name.clone())
                    .or_insert_with(|| {
                        log!(
                            self.state.logger.clone(),
                            "Initializing new Unique variable '{}'",
                            unique_name
                        );

                        if bit_size == 1 {
                            ConcolicVar {
                                concrete: ConcreteVar::Bool(false),
                                symbolic: SymbolicVar::Bool(Bool::from_bool(self.context, false)),
                                ctx: self.context,
                            }
                        } else if bit_size > 64 {
                            let symbolic_values = vec![
                                BV::from_u64(self.context, 0, 64);
                                bit_size.div_ceil(64).try_into().unwrap()
                            ];
                            let mut combined_bv = symbolic_values[0].clone();
                            for bv in symbolic_values.iter().skip(1) {
                                combined_bv = bv.concat(&combined_bv);
                            }
                            ConcolicVar {
                                concrete: ConcreteVar::LargeInt(vec![
                                    0;
                                    bit_size
                                        .div_ceil(64)
                                        .try_into()
                                        .unwrap()
                                ]),
                                symbolic: SymbolicVar::LargeInt(symbolic_values),
                                ctx: self.context,
                            }
                        } else {
                            ConcolicVar {
                                concrete: ConcreteVar::Int(0),
                                symbolic: SymbolicVar::Int(BV::from_u64(self.context, 0, bit_size)),
                                ctx: self.context,
                            }
                        }
                    });

                // Ensure Correct Symbolic Type
                let final_symbolic = match &unique_var.symbolic {
                    SymbolicVar::Bool(b) => SymbolicVar::Bool(b.clone()), // Ensure boolean stays boolean
                    SymbolicVar::Int(bv) => SymbolicVar::Int(bv.clone()),
                    SymbolicVar::LargeInt(bv_vec) => {
                        if bit_size <= 64 {
                            SymbolicVar::Int(bv_vec[0].clone())
                        } else {
                            let mut combined_bv = bv_vec[0].clone();
                            for bv in bv_vec.iter().skip(1) {
                                combined_bv = bv.concat(&combined_bv); // high <- low (little endian)
                            }
                            SymbolicVar::LargeInt(vec![combined_bv])
                        }
                    }
                    SymbolicVar::Float(f) => SymbolicVar::Float(f.clone()),
                    SymbolicVar::Slice(s) => SymbolicVar::Slice(s.clone()),
                };

                let final_var = ConcolicVar {
                    concrete: unique_var.concrete.clone(),
                    symbolic: final_symbolic,
                    ctx: self.context,
                };

                log!(
                    self.state.logger.clone(),
                    "Retrieved unique variable: {:?} with symbolic size: {}",
                    final_var.concrete,
                    bit_size
                );
                Ok(ConcolicEnum::ConcolicVar(final_var))
            }
            Var::Const(value) => {
                log!(
                    self.state.logger.clone(),
                    "Varnode is a constant with value: {}",
                    value
                );
                // First, parse the constant as an unsigned 64-bit value.
                let parsed_value_u64 = if let Some(hex) = value.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)
                } else {
                    value.parse::<u64>()
                }
                .map_err(|e| format!("Failed to parse value '{}' as u64: {}", value, e))?;

                // Interpret the parsed value as signed, based on the requested bit size.
                let parsed_value: i64 = if bit_size < 64 {
                    // For example, if bit_size is 32, then the sign bit is 1 << 31.
                    let sign_bit = 1u64 << (bit_size - 1);
                    let mask = (1u64 << bit_size) - 1;
                    let x = parsed_value_u64 & mask;
                    if x & sign_bit != 0 {
                        // Negative value: subtract 1 << bit_size
                        (x as i64) - ((1u64 << bit_size) as i64)
                    } else {
                        x as i64
                    }
                } else {
                    // For 64 bits, we assume the value is already in two's complement form.
                    parsed_value_u64 as i64
                };

                log!(
                    self.state.logger.clone(),
                    "Parsed value (signed): {}",
                    parsed_value
                );

                // For the concrete part, we want to keep the bit pattern in the proper width.
                // For sizes <64, we re-encode the signed value as two's complement in bit_size bits.
                let concrete_val = if bit_size < 64 {
                    let mask = (1u64 << bit_size) - 1;
                    if parsed_value < 0 {
                        ((parsed_value + (1 << bit_size)) as u64) & mask
                    } else {
                        (parsed_value as u64) & mask
                    }
                } else {
                    parsed_value_u64
                };

                // Build the symbolic value using BV::from_i64 (which takes a signed i64)
                let parsed_value_symbolic = BV::from_i64(self.context, parsed_value, bit_size);

                let mem_value = MemoryValue {
                    concrete: concrete_val,
                    symbolic: parsed_value_symbolic,
                    size: bit_size,
                };

                log!(
                    self.state.logger.clone(),
                    "Constant treated as memory value: {:?} with symbolic size {:?}",
                    mem_value.concrete,
                    mem_value.symbolic.get_size()
                );
                Ok(ConcolicEnum::MemoryValue(mem_value))
            }
            Var::MemoryRam => {
                log!(self.state.logger.clone(), "Varnode is MemoryRam");
                // Assuming MemoryRam represents general memory starting at address 0
                // let mem_value = self.state.memory.read_value(0, bit_size)
                //     .map_err(|e| format!("Failed to read MemoryRam: {:?}", e))?;
                //log!(self.state.logger.clone(), "MemoryRam treated as general memory space, retrieved: {:?}", mem_value.concrete);
                Ok(ConcolicEnum::MemoryValue(MemoryValue {
                    concrete: 0,
                    symbolic: BV::new_const(self.context, "MemoryRam", bit_size),
                    size: bit_size,
                }))
            }
            Var::Memory(addr) => {
                log!(
                    self.state.logger.clone(),
                    "Varnode is a specific memory address: 0x{:x}",
                    addr
                );

                // Read the value from memory
                let mem_value = self
                    .state
                    .memory
                    .read_value(*addr, bit_size, &mut self.state.logger.clone())
                    .map_err(|e| {
                        format!("Failed to read memory at address 0x{:x}: {:?}", addr, e)
                    })?;

                log!(
                    self.state.logger.clone(),
                    "Retrieved memory value: {:x} with symbolic size: {:?}",
                    mem_value.concrete,
                    mem_value.symbolic.get_size()
                );
                // The type is ConcolicVar because the memory value can be a large integer so MemoryValue type is not enough
                Ok(ConcolicEnum::ConcolicVar(mem_value))
            }
        }
    }

    // Extracts a value from a register and creates a new concolic value
    /// Find the containing register for a given offset
    /// Returns (base_offset, size_bits) if found
    fn find_containing_register_offset(&self, offset: u64) -> Option<(u64, u32)> {
        let cpu_state_guard = match self.state.cpu_state.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };

        let mut containing: Option<(u64, u32)> = None;
        for (base, &(_, size_bits)) in cpu_state_guard.register_map.iter() {
            let size_bytes = (size_bits as u64) / 8;
            if offset >= *base && offset < (*base + size_bytes) {
                if let Some((best_base, _)) = containing {
                    if *base > best_base {
                        containing = Some((*base, size_bits));
                    }
                } else {
                    containing = Some((*base, size_bits));
                }
            }
        }
        containing
    }

    /// Extract a portion from a CpuConcolicValue (overlay-aware extraction)
    fn extract_from_cpu_value(
        &self,
        original_register: &CpuConcolicValue<'ctx>,
        offset: u64,
        bit_size: u32,
    ) -> Result<ConcolicEnum<'ctx>, String> {
        // Find the base register offset to calculate bit_offset
        let containing_offset = self
            .find_containing_register_offset(offset)
            .ok_or_else(|| format!("No containing register found for offset 0x{:x}", offset))?;

        let base_register_offset = containing_offset.0;
        let bit_offset = (offset - base_register_offset) * 8; // Calculate the bit offset within the register

        match &original_register.concrete {
            ConcreteVar::Int(value) => {
                // Handle the concrete extraction
                let mask: u64 = if bit_size < 64 {
                    (1u64 << bit_size) - 1
                } else {
                    u64::MAX
                };
                let extracted_value = (*value >> bit_offset) & mask;

                // Symbolic extraction — only simplify if the source is non-trivial.
                // For a numeral BV, extract() already produces a numeral and
                // simplify() is a wasted O(tree_size) walk.
                let symbolic_bv = original_register.symbolic.to_bv(self.context);
                let high_bit = (bit_offset + u64::from(bit_size) - 1) as u32;
                let low_bit = bit_offset as u32;

                let raw_extract = symbolic_bv.extract(high_bit, low_bit);
                let extracted_symbolic = if raw_extract.as_u64().is_some() {
                    raw_extract
                } else {
                    raw_extract.simplify()
                };

                if extracted_symbolic.get_z3_ast().is_null() {
                    return Err("Symbolic extraction resulted in an invalid state".to_string());
                }

                Ok(ConcolicEnum::CpuConcolicValue(CpuConcolicValue {
                    concrete: ConcreteVar::Int(extracted_value),
                    symbolic: SymbolicVar::Int(extracted_symbolic),
                    ctx: self.context,
                }))
            }
            ConcreteVar::LargeInt(values) => {
                // Handle the concrete extraction from LargeInt
                let start_bit = bit_offset;
                let end_bit = start_bit + u64::from(bit_size) - 1;
                let extracted_concrete =
                    CpuState::extract_bits_from_large_int(values, start_bit, end_bit);

                // Extract the symbolic value
                if let SymbolicVar::LargeInt(ref bvs) = original_register.symbolic {
                    let raw_sym = CpuState::extract_symbolic_bits_from_large_int(
                        self.context,
                        bvs,
                        start_bit,
                        end_bit,
                    );
                    // Only simplify non-trivial symbolic expressions
                    let extracted_symbolic = match &raw_sym {
                        SymbolicVar::Int(bv) if bv.as_u64().is_some() => raw_sym,
                        _ => raw_sym.simplify(),
                    };

                    Ok(ConcolicEnum::CpuConcolicValue(CpuConcolicValue {
                        concrete: extracted_concrete,
                        symbolic: extracted_symbolic,
                        ctx: self.context,
                    }))
                } else {
                    Err("Expected LargeInt symbolic variable".to_string())
                }
            }
            _ => Err("Unsupported concrete variable type for extraction".to_string()),
        }
    }

    fn extract_and_create_concolic_value(
        &self,
        cpu_state_guard: &MutexGuard<'_, CpuState<'ctx>>,
        original_offset: u64,
        bit_size: u32,
    ) -> Result<ConcolicEnum<'ctx>, String> {
        // Normalize certain SIMD varnode offsets (XMM/YMM) using dynamic info from the register map.
        // Some pcode streams use a stride equal to 2x the modeled YMM size (e.g., 64B) per register row.
        // We detect the YMM series and map the offset into the modeled row without relying on fixed constants.
        let offset = {
            // Collect YMM registers and their offsets/sizes
            let mut ymm_entries: Vec<(u64, u32)> = cpu_state_guard
                .register_map
                .iter()
                .filter_map(|(off, (name, sz))| {
                    if name.starts_with("YMM") {
                        Some((*off, *sz))
                    } else {
                        None
                    }
                })
                .collect();
            ymm_entries.sort_by_key(|(off, _)| *off);

            if let Some((base_off, base_sz_bits)) = ymm_entries.first().cloned() {
                let reg_size_bytes = (base_sz_bits as u64) / 8; // expected YMM size in bytes
                let count = ymm_entries.len() as u64;
                if reg_size_bytes > 0 {
                    let alt_stride = reg_size_bytes * 2; // common pcode stride for XMM/YMM rows
                    let total_alt_span = alt_stride * count;
                    if original_offset >= base_off && original_offset < base_off + total_alt_span {
                        let delta = original_offset - base_off;
                        let reg_idx = delta / alt_stride;
                        let lane_off = delta % alt_stride;
                        let low_lane_bytes = std::cmp::min(16u64, reg_size_bytes / 2); // XMM lower lane
                        base_off + reg_idx * reg_size_bytes + (lane_off % low_lane_bytes)
                    } else {
                        original_offset
                    }
                } else {
                    original_offset
                }
            } else {
                original_offset
            }
        };

        // Find a register that CONTAINS the requested [offset, offset+bit_size) range
        let mut containing: Option<(u64, u32)> = None;
        for (base, &(_, size_bits)) in cpu_state_guard.register_map.iter() {
            let size_bytes = (size_bits as u64) / 8;
            if offset >= *base && (offset + (bit_size as u64).div_ceil(8)) <= (*base + size_bytes) {
                if let Some((best_base, _)) = containing {
                    if *base > best_base {
                        containing = Some((*base, size_bits));
                    }
                } else {
                    containing = Some((*base, size_bits));
                }
            }
        }

        let (base_register_offset, register_size) = containing
            .ok_or_else(|| format!("No containing register found for offset 0x{:x}", offset))?;

        log!(
            self.state.logger.clone(),
            "Containing register found at offset 0x{:x} with size {}",
            base_register_offset,
            register_size
        );

        let bit_offset = (offset - base_register_offset) * 8; // Calculate the bit offset within the register

        let original_register = cpu_state_guard
            .get_register_by_offset(base_register_offset, register_size)
            .ok_or_else(|| {
                format!(
                    "Failed to retrieve register for extraction at offset 0x{:x}",
                    base_register_offset
                )
            })?;

        match &original_register.concrete {
            ConcreteVar::Int(value) => {
                // Handle the concrete extraction
                let mask: u64 = if bit_size < 64 {
                    (1u64 << bit_size) - 1
                } else {
                    u64::MAX
                };
                let extracted_value = (*value >> bit_offset) & mask;

                // Symbolic extraction — skip simplify for numeral BVs
                let symbolic_bv = original_register.symbolic.to_bv(cpu_state_guard.ctx);
                let high_bit = (bit_offset + u64::from(bit_size) - 1) as u32;
                let low_bit = bit_offset as u32;

                let raw_extract = symbolic_bv.extract(high_bit, low_bit);
                let extracted_symbolic = if raw_extract.as_u64().is_some() {
                    raw_extract
                } else {
                    raw_extract.simplify()
                };

                if extracted_symbolic.get_z3_ast().is_null() {
                    return Err("Symbolic extraction resulted in an invalid state".to_string());
                }

                Ok(ConcolicEnum::CpuConcolicValue(CpuConcolicValue {
                    concrete: ConcreteVar::Int(extracted_value),
                    symbolic: SymbolicVar::Int(extracted_symbolic),
                    ctx: cpu_state_guard.ctx,
                }))
            }
            ConcreteVar::LargeInt(values) => {
                // Handle the concrete extraction from LargeInt
                let start_bit = bit_offset;
                let end_bit = start_bit + u64::from(bit_size) - 1;
                let extracted_concrete =
                    CpuState::extract_bits_from_large_int(values, start_bit, end_bit);

                // Use extract_symbolic_bits_from_large_int to extract the symbolic value
                if let SymbolicVar::LargeInt(ref bvs) = original_register.symbolic {
                    let raw_sym = CpuState::extract_symbolic_bits_from_large_int(
                        cpu_state_guard.ctx,
                        bvs,
                        start_bit,
                        end_bit,
                    );
                    // Only simplify non-trivial symbolic expressions
                    let extracted_symbolic = match &raw_sym {
                        SymbolicVar::Int(bv) if bv.as_u64().is_some() => raw_sym,
                        _ => raw_sym.simplify(),
                    };

                    Ok(ConcolicEnum::CpuConcolicValue(CpuConcolicValue {
                        concrete: extracted_concrete,
                        symbolic: extracted_symbolic,
                        ctx: cpu_state_guard.ctx,
                    }))
                } else {
                    Err("Expected LargeInt symbolic variable".to_string())
                }
            }
            _ => Err("Unsupported concrete variable type for extraction".to_string()),
        }
    }

    pub fn handle_output(
        &mut self,
        output_varnode: Option<&Varnode>,
        result_value: ConcolicVar<'ctx>,
    ) -> Result<(), String> {
        if let Some(varnode) = output_varnode {
            // Resize the result_value according to the output size specification
            let bit_size = varnode.size.to_bitvector_size(); // size in bits

            match &varnode.var {
                Var::Unique(id) => {
                    log!(
                        self.state.logger.clone(),
                        "Writing {:x} to the unique variable with ID: 0x{:x}",
                        result_value.concrete.to_u64(),
                        id
                    );
                    let unique_name = format!("Unique(0x{:x})", id);
                    self.unique_variables
                        .insert(unique_name, result_value.clone());
                    log!(self.state.logger.clone(), "Updated unique variable: Unique(0x{:x}) with concrete part : {:x}, concrete size {} bits and symbolic size {} bits", id, result_value.concrete.to_u64(), bit_size, result_value.symbolic.get_size());
                    Ok(())
                }
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");

                    // Normalize SIMD register offsets (XMM/YMM/ZMM) using the CPU state helper
                    let write_offset = {
                        let cpu_state_guard = self.state.cpu_state.lock().unwrap();
                        cpu_state_guard.map_simd_virtual_offset(*offset)
                    };

                    // Use overlay-aware register write (writes to overlay if active, otherwise base)
                    match self.set_register_overlay_aware(
                        write_offset,
                        result_value.clone(),
                        bit_size,
                    ) {
                        Ok(_) => {
                            // Verify using overlay-aware read
                            if let Some(register) =
                                self.get_register_overlay_aware(write_offset, bit_size)
                            {
                                log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with concrete value 0x{:x}, concrete size {} bits and symbolic size {:?} bits", write_offset, register.concrete.to_u64(), bit_size, register.symbolic.get_size());
                            }
                            Ok(())
                        }
                        Err(e) => {
                            let error_msg = format!(
                                "Failed to update register at offset 0x{:x}: {}",
                                write_offset, e
                            );
                            log!(self.state.logger.clone(), "{}", error_msg);
                            Err(error_msg)
                        }
                    }
                }
                Var::Memory(addr) => {
                    log!(
                        self.state.logger.clone(),
                        "Output is a Memory type at address 0x{:x}",
                        addr
                    );

                    // Extract concrete value
                    let concrete_value = result_value.concrete.to_u64();

                    // Extract symbolic value
                    let symbolic_bv = result_value.symbolic.to_bv(self.context);

                    // Ensure symbolic value size matches bit_size
                    let symbolic_size = symbolic_bv.get_size();
                    log!(
                        self.state.logger.clone(),
                        "symbolic_size: {}, bit_size: {}",
                        symbolic_size,
                        bit_size
                    );
                    if symbolic_size != bit_size {
                        return Err(format!(
                            "Symbolic size {} does not match bit size {}",
                            symbolic_size, bit_size
                        ));
                    }

                    // Create a MemoryValue
                    let mem_value = MemoryValue {
                        concrete: concrete_value,
                        symbolic: symbolic_bv.clone(),
                        size: bit_size,
                    };

                    // Write the MemoryValue to memory
                    match self.state.memory.write_value(*addr, &mem_value) {
                        Ok(_) => {
                            log!(self.state.logger.clone(), "Wrote value 0x{:x} to memory at address 0x{:x}, with symbolic part : {:?} and symbolic size {:?} bits", concrete_value, addr, symbolic_bv.simplify(), symbolic_size);
                            Ok(())
                        }
                        Err(e) => {
                            let error_msg = format!(
                                "Failed to write to memory at address 0x{:x}: {:?}",
                                addr, e
                            );
                            log!(self.state.logger.clone(), "{}", error_msg);
                            Err(error_msg)
                        }
                    }
                }
                _ => {
                    let error_msg = "Output type is unsupported".to_string();
                    log!(self.state.logger.clone(), "{}", error_msg);
                    Err(error_msg)
                }
            }
        } else {
            Err("No output varnode specified".to_string())
        }
    }

    // Handle branch operation
    pub fn handle_branch(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Branch || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for BRANCH".to_string());
        }

        let branch_target_varnode = &instruction.inputs[0];
        log!(
            self.state.logger.clone(),
            "* Fetching branch target from instruction.input[0]"
        );

        // Check if this is an internal P-code jump (Const varnode) or an absolute address jump
        match &branch_target_varnode.var {
            Var::Const(value) => {
                // This is an internal P-code jump offset (can be negative)
                log!(
                    self.state.logger.clone(),
                    "Branch target is a constant: {:?}, treating as internal P-code line offset",
                    value
                );
                let value_string = value.to_string();
                let value_str = value_string.trim_start_matches("0x");

                let value_u64 = match u64::from_str_radix(value_str, 16) {
                    Ok(parsed) => {
                        log!(
                            self.state.logger.clone(),
                            "Parsed branch offset: 0x{:x} (signed: {})",
                            parsed,
                            parsed as i64
                        );
                        parsed
                    }
                    Err(e) => {
                        return Err(format!("Failed to parse constant as u64: {:?}", e));
                    }
                };

                // Set the internal jump offset (can be negative for backward jumps)
                self.pcode_internal_lines_to_be_jumped = value_u64 as i64;
                log!(
                    self.state.logger.clone(),
                    "BRANCH: Setting internal P-code jump offset to {} lines",
                    self.pcode_internal_lines_to_be_jumped
                );

                // Create concolic variable for logging
                let current_addr_hex = self
                    .current_address
                    .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                let result_var_name = format!(
                    "{}-{:02}-branch",
                    current_addr_hex, self.instruction_counter
                );
                let symbolic_var = SymbolicVar::from_u64(self.context, value_u64, 64);
                self.state.create_or_update_concolic_variable_int(
                    &result_var_name,
                    value_u64,
                    symbolic_var,
                );
            }
            _ => {
                // This is an absolute address jump (Memory, Register, or Unique)
                let branch_target_address =
                    self.extract_branch_target_address(branch_target_varnode, instruction.clone())?;

                log!(
                    self.state.logger.clone(),
                    "Branch target is an absolute address: 0x{:x}",
                    branch_target_address
                );

                // Create concolic variable for branch target and update RIP register
                let symbolic_var = SymbolicVar::from_u64(self.context, branch_target_address, 64)
                    .to_bv(self.context);
                let branch_target_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                    branch_target_address,
                    symbolic_var,
                    self.context,
                );

                // Update RIP to branch target (overlay-aware)
                self.set_register_overlay_aware(0x288, branch_target_concolic.clone(), 64)?;

                // Log the branch decision as a concolic variable for tracking
                let current_addr_hex = self
                    .current_address
                    .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                let result_var_name = format!(
                    "{}-{:02}-branch",
                    current_addr_hex, self.instruction_counter
                );
                self.state.create_or_update_concolic_variable_int(
                    &result_var_name,
                    branch_target_address,
                    branch_target_concolic.symbolic,
                );

                log!(
                    self.state.logger.clone(),
                    "Updated RIP register with branch target: 0x{:x}",
                    branch_target_address
                );
            }
        }

        // Update the instruction counter
        self.instruction_counter += 1;

        Ok(())
    }

    // However, this function is used in mains.rs when doing checks related to CBRANCH instruction
    pub fn from_varnode_var_to_branch_address(&mut self, varnode: &Varnode) -> Result<u64, String> {
        match &varnode.var {
            Var::Memory(addr) => Ok(*addr),
            Var::Const(value) => {
                // Parse as unsigned first.
                let parsed_value_u64 = if let Some(hex) = value.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)
                } else {
                    value.parse::<u64>()
                }
                .map_err(|e| format!("Failed to parse value '{}' as u64: {}", value, e))?;

                // For a Word (32-bit) constant, manually sign-extend.
                let bit_size = varnode.size.to_bitvector_size(); // e.g. 32 for Word
                let parsed_value: i64 = if bit_size < 64 {
                    let sign_bit = 1u64 << (bit_size - 1);
                    let mask = (1u64 << bit_size) - 1;
                    let x = parsed_value_u64 & mask;
                    if x & sign_bit != 0 {
                        (x as i64) - ((1u64 << bit_size) as i64)
                    } else {
                        x as i64
                    }
                } else {
                    parsed_value_u64 as i64
                };

                Ok(parsed_value as u64)
            }
            Var::Register(offset, size) => {
                // Validate that the register size matches the expected size
                let expected_bit_size = 64; // branch targets are 64-bit addresses
                if size.to_bitvector_size() != expected_bit_size {
                    return Err(format!(
                        "Unsupported register bit size for INT_SLESS: {}, expected {}",
                        size.to_bitvector_size(),
                        expected_bit_size
                    ));
                }

                // Retrieve the register's concrete and symbolic values
                let cpu_state_guard: MutexGuard<'_, CpuState<'ctx>> =
                    self.state.cpu_state.lock().unwrap();
                let register_value = cpu_state_guard
                    .get_register_by_offset(*offset, expected_bit_size)
                    .ok_or_else(|| {
                        format!("Failed to retrieve register by offset 0x{:x}", offset)
                    })?;

                let concrete_value = match register_value.concrete {
                    ConcreteVar::Int(val) => val,
                    _ => {
                        return Err(format!(
                            "Unsupported concrete type for register at offset 0x{:x}",
                            offset
                        ))
                    }
                };

                Ok(concrete_value)
            }
            Var::Unique(id) => {
                let unique_name = format!("Unique(0x{:x})", id);
                let unique_var = self.unique_variables.get(&unique_name).ok_or_else(|| {
                    format!("Failed to retrieve unique variable with id 0x{:x}", id)
                })?;

                let concrete_value = match unique_var.concrete {
                    ConcreteVar::Int(val) => val,
                    _ => {
                        return Err(format!(
                            "Unsupported concrete type for unique variable with id 0x{:x}",
                            id
                        ))
                    }
                };

                Ok(concrete_value)
            }
            _ => Err(format!(
                "Branch instruction does not support this variable type: {:?}",
                varnode.var
            )),
        }
    }

    // For BRANCHIND, CALLIND, BRANCH and CBRANCH instruction
    //
    // IMPORTANT: This helper is **pure** w.r.t. CPU state – it must NOT modify RIP.
    // All control‑flow updates (including in overlay mode) are done by the
    // callers (e.g. `handle_branch`, `handle_callind`) via
    // `set_register_overlay_aware`. Previously this function was also writing
    // to RIP directly, which broke overlay isolation by leaking speculative
    // RIP values into the base state.
    pub fn extract_branch_target_address(
        &mut self,
        varnode: &Varnode,
        instruction: Inst,
    ) -> Result<u64, String> {
        match &varnode.var {
            Var::Memory(addr) => {
                log!(
                    self.state.logger.clone(),
                    "Branch target is a specific memory address: 0x{:x}",
                    addr
                );

                // - BRANCHIND / CALLIND *[ram]addr  => dereference pointer and use
                //   the *value* as the branch target address.
                // - BRANCH / CBRANCH *[ram]addr    => treat the memory address
                //   itself as the branch target (no dereference).
                if instruction.opcode == Opcode::BranchInd || instruction.opcode == Opcode::CallInd
                {
                    // Dereference the memory address to obtain the indirect target.
                    let mem_value = self
                        .state
                        .memory
                        .read_value(
                            *addr,
                            varnode.size.to_bitvector_size(),
                            &mut self.state.logger.clone(),
                        )
                        .map_err(|e| {
                            format!("Failed to read memory at address 0x{:x}: {:?}", addr, e)
                        })?;
                    let deref_concolic =
                        ConcolicVar::new_from_memory_value(&mem_value.to_memory_value_u64());
                    let concrete_target = deref_concolic.concrete.to_u64();
                    Ok(concrete_target)
                } else {
                    // Direct branch / CBRANCH to the memory address itself.
                    Ok(*addr)
                }
            }
            Var::Const(value) => {
                log!(self.state.logger.clone(), "Branch target is a constant value indicating the number of lines to jump: {:?}", value);
                // Parse as unsigned first.
                let parsed_value_u64 = if let Some(hex) = value.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)
                } else {
                    value.parse::<u64>()
                }
                .map_err(|e| format!("Failed to parse value '{}' as u64: {}", value, e))?;

                // For a Word (32-bit) constant, manually sign-extend.
                let bit_size = varnode.size.to_bitvector_size(); // e.g. 32 for Word
                let parsed_value: i64 = if bit_size < 64 {
                    let sign_bit = 1u64 << (bit_size - 1);
                    let mask = (1u64 << bit_size) - 1;
                    let x = parsed_value_u64 & mask;
                    if x & sign_bit != 0 {
                        (x as i64) - ((1u64 << bit_size) as i64)
                    } else {
                        x as i64
                    }
                } else {
                    parsed_value_u64 as i64
                };
                log!(
                    self.state.logger.clone(),
                    "Parsed branch target (signed): {}",
                    parsed_value
                );

                Ok(parsed_value as u64)
            }
            Var::Register(offset, size) => {
                log!(
                    self.state.logger.clone(),
                    "Branch target is a Register at offset: 0x{:x} with size: {:?}",
                    offset,
                    size
                );

                // Validate that the register size matches the expected size
                let expected_bit_size = 64; // Branch targets are 64-bit addresses
                if size.to_bitvector_size() != expected_bit_size {
                    return Err(format!(
                        "Unsupported register bit size for INT_SLESS: {}, expected {}",
                        size.to_bitvector_size(),
                        expected_bit_size
                    ));
                }

                // Retrieve the register's concrete and symbolic values
                let cpu_state_guard = self.state.cpu_state.lock().unwrap();
                let register_value = cpu_state_guard
                    .get_register_by_offset(*offset, expected_bit_size)
                    .ok_or_else(|| {
                        format!("Failed to retrieve register by offset 0x{:x}", offset)
                    })?;

                let concrete_value = match register_value.concrete {
                    ConcreteVar::Int(val) => val,
                    _ => {
                        return Err(format!(
                            "Unsupported concrete type for register at offset 0x{:x}",
                            offset
                        ))
                    }
                };

                // Note: We do NOT update RIP here. This function is pure w.r.t. CPU state.
                // The caller (e.g., handle_branch, handle_callind) will update RIP via
                // set_register_overlay_aware to ensure proper overlay isolation.

                log!(
                    self.state.logger.clone(),
                    "Extracted branch target address 0x{:x} from register at offset 0x{:x}",
                    concrete_value,
                    offset
                );

                Ok(concrete_value)
            }
            Var::Unique(id) => {
                let unique_name = format!("Unique(0x{:x})", id);
                let unique_var = self.unique_variables.get(&unique_name).ok_or_else(|| {
                    format!("Failed to retrieve unique variable with id 0x{:x}", id)
                })?;

                let concrete_value = match unique_var.concrete {
                    ConcreteVar::Int(val) => val,
                    _ => {
                        return Err(format!(
                            "Unsupported concrete type for unique variable with id 0x{:x}",
                            id
                        ))
                    }
                };

                Ok(concrete_value)
            }
            _ => Err(format!(
                "Branch instruction does not support this variable type: {:?}",
                varnode.var
            )),
        }
    }

    // Handle indirect branch operation
    pub fn handle_branchind(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::BranchInd || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for BRANCHIND".to_string());
        }

        log!(
            self.state.logger.clone(),
            "* Fetching branch target from instruction.input[0]"
        );
        let branch_target_varnode = &instruction.inputs[0];
        let branch_target_address =
            self.extract_branch_target_address(branch_target_varnode, instruction.clone())?;

        log!(
            self.state.logger.clone(),
            "Branching to address 0x{:x}",
            branch_target_address
        );

        // Create concolic variable for branch target and update RIP register
        let symbolic_var =
            SymbolicVar::from_u64(self.context, branch_target_address, 64).to_bv(self.context);
        let branch_target_concolic = ConcolicVar::new_concrete_and_symbolic_int(
            branch_target_address,
            symbolic_var,
            self.context,
        );

        // Update RIP to branch target (overlay-aware)
        self.set_register_overlay_aware(0x288, branch_target_concolic.clone(), 64)?;

        // Update the instruction counter
        self.instruction_counter += 1;

        // Log the branch decision as a concolic variable for tracking
        let current_addr_hex = self
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!(
            "{}-{:02}-branchind",
            current_addr_hex, self.instruction_counter
        );
        self.state.create_or_update_concolic_variable_int(
            &result_var_name,
            branch_target_address,
            branch_target_concolic.symbolic,
        );

        log!(
            self.state.logger.clone(),
            "Updated RIP register with indirect branch target: 0x{:x}",
            branch_target_address
        );

        Ok(())
    }

    // Helper function to check if any tracked symbolic variable is present in a Bool expression
    // NOTE: Avoid simplify() - it can hang on complex expressions!
    fn contains_tracked_symbolic_variable(&self, symbolic_expr: &Bool<'ctx>) -> bool {
        // Quick check: if no symbolic arguments tracked, return false immediately
        if self.function_symbolic_arguments.is_empty() {
            return false;
        }

        // Format without simplify to avoid hanging
        let expr_string = format!("{:?}", symbolic_expr);

        // Match on the formatted Z3 BV name (e.g. "b_ptr!141"), not the
        // HashMap key (e.g. "b.header"), to avoid spurious substring hits.
        for (arg_name, sym_var) in self.function_symbolic_arguments.iter() {
            let z3_name = match sym_var {
                SymbolicVar::Int(bv) => format!("{:?}", bv),
                _ => arg_name.clone(),
            };
            if expr_string.contains(&z3_name) {
                log!(
                    self.state.logger.clone(),
                    "Found tracked symbolic variable '{}' in expression",
                    arg_name
                );
                return true;
            }
        }
        false
    }

    // Check if a symbolic pointer address could be NULL using the Z3 solver.
    // Active on both the concrete path and during overlay execution.
    //
    // DESIGN: We check the BASE tracked variable for NULL, not the derived
    // expression.  If b_ptr can be nil, then any address derived from it
    // (b_ptr + offset, b_ptr[index], etc.) is also an invalid memory access.
    // This avoids false positives (solver finding exotic non-nil values that
    // make a complex expression zero) and avoids calling simplify() entirely.
    //
    // The only Z3 operation is format!("{:?}") once to find which tracked
    // variable appears in the expression.  No simplify() is ever called.
    //
    // Per-variable caching ensures the solver is invoked at most once per
    // tracked variable per constraint level.  For Go struct-pointer arguments
    // (method receivers) the cache is pre-seeded with UNSAT at initialization,
    // so the solver is never invoked at all.
    fn check_symbolic_null_dereference(
        &mut self,
        pointer_concolic: &ConcolicEnum<'ctx>,
        pointer_concrete: u64,
        operation: &str,
        current_inst: &Inst,
    ) -> bool {
        if self.function_symbolic_arguments.is_empty() {
            return false;
        }

        let pointer_bv = pointer_concolic.get_symbolic_value_bv(self.context);

        // Fast path: if the BV is a Z3 numeral constant, no tracked variable
        // is involved — skip without formatting the expression tree.
        if pointer_bv.as_u64().is_some() {
            return false;
        }

        // Format the expression ONCE to find which tracked variable appears.
        // We intentionally NEVER call simplify() — it can be very expensive
        // for large expression trees and is unnecessary: we check the BASE
        // tracked variable for NULL, not the derived expression.
        let expr_string = format!("{:?}", pointer_bv);

        // Find the tracked symbolic variable whose Z3 name appears in the
        // expression.  We match on the *formatted BV* (e.g. "b_ptr!141"),
        // NOT on the HashMap key (e.g. "b.header"), because:
        //   • Keys may contain dots while Z3 names use underscores
        //   • Short keys ("b") could spuriously match inside longer
        //     Z3 names ("b_ptr!141")
        // Using the full Z3 name eliminates both problems.
        let mut base_var_name: Option<String> = None;
        let mut base_bv: Option<BV<'ctx>> = None;

        for (arg_name, sym_var) in self.function_symbolic_arguments.iter() {
            if let SymbolicVar::Int(bv) = sym_var {
                let bv_z3_name = format!("{:?}", bv);
                if expr_string.contains(&bv_z3_name) {
                    base_var_name = Some(arg_name.clone());
                    base_bv = Some(bv.clone());
                    break;
                }
            }
        }

        let (base_var_name, base_bv) = match (base_var_name, base_bv) {
            (Some(name), Some(bv)) => (name, bv),
            _ => return false, // No tracked variable — purely concrete or untracked expression
        };

        // Use the base variable name as cache key — all derived expressions
        // from the same base share one NULL check result.
        let current_constraint_len = self.constraint_vector.len();
        if let Some(&(sat, cached_len)) = self.null_check_cache.get(&base_var_name) {
            if sat {
                // Already confirmed as nullable — vulnerability already reported
                return false;
            }
            if cached_len == current_constraint_len {
                // Already checked UNSAT at this constraint level — skip
                return false;
            }
        }

        log!(
            self.state.logger.clone(),
            "[NULL-CHECK] Checking if '{}' can be NULL ({} at 0x{:x}, concrete ptr: 0x{:x}, constraints: {})",
            base_var_name,
            operation,
            self.current_address.unwrap_or(0),
            pointer_concrete,
            current_constraint_len
        );

        let addr_hex = self.current_address.unwrap_or(0);

        match crate::state::evaluate_z3::evaluate_args_z3(
            self,
            current_inst,
            None,           // no conditional flag for NULL checks
            Some(addr_hex), // instruction address
            None,           // no branch target
            Some(addr_hex), // use current address as "panic address" for SAT file
            Some(&base_bv), // check if the base variable can be NULL
        ) {
            Ok(true) => {
                // SAT — vulnerability found and already reported by evaluate_args_z3
                self.null_check_cache
                    .insert(base_var_name, (true, current_constraint_len));
                true
            }
            Ok(false) => {
                // UNSAT or Unknown — base variable cannot be NULL
                let var_name_for_log = base_var_name.clone();
                self.null_check_cache
                    .insert(base_var_name, (false, current_constraint_len));
                log!(
                    self.state.logger.clone(),
                    "[NULL-CHECK] '{}' cannot be NULL (UNSAT)",
                    var_name_for_log
                );
                false
            }
            Err(e) => {
                log!(
                    self.state.logger.clone(),
                    "[NULL-CHECK] Error checking '{}': {}",
                    base_var_name.clone(),
                    e
                );
                false
            }
        }
    }

    // Handle conditional branch operation
    pub fn handle_cbranch(
        &mut self,
        instruction: Inst,
        next_inst_in_map: u64,
    ) -> Result<(), String> {
        if instruction.opcode != Opcode::CBranch || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for CBRANCH".to_string());
        }

        // Fetch the branch target (input0)
        log!(
            self.state.logger.clone(),
            "* Fetching branch target from instruction.input[0]"
        );
        let branch_target_varnode = &instruction.inputs[0];

        let branch_condition_concolic = self
            .varnode_to_concolic(&instruction.inputs[1])
            .map_err(|e| e.to_string())?
            .to_concolic_var()
            .unwrap();

        // Extract a plain Rust bool from the concolic condition's concrete part
        let condition_concrete_bool = branch_condition_concolic.concrete.to_bool();
        log!(
            self.state.logger.clone(),
            "Branch condition concrete: {}",
            condition_concrete_bool
        );

        // Extract the meaningful symbolic condition using AST inspection
        log!(
            self.state.logger.clone(),
            "Branching condition symbolic: {:?}",
            branch_condition_concolic.symbolic.simplify()
        );

        let condition_symbolic = match &branch_condition_concolic.symbolic {
            SymbolicVar::Int(bv) => {
                log!(
                    self.state.logger.clone(),
                    "Extracting condition from Int BV: {:?}",
                    bv.simplify()
                );
                extract_underlying_condition_from_flag_ast(
                    &bv.simplify(),
                    condition_concrete_bool,
                    &mut self.state.logger,
                )
            }
            SymbolicVar::Bool(b) => {
                log!(
                    self.state.logger.clone(),
                    "Branch condition is a Bool: {:?}",
                    b
                );
                // For Bool types, use the boolean directly based on the path taken
                if condition_concrete_bool {
                    b.clone()
                } else {
                    b.not()
                }
            }
            _ => {
                // Fallback to smart conversion
                let smart_bool = branch_condition_concolic.symbolic.to_bool_ast_smart();
                if condition_concrete_bool {
                    smart_bool
                } else {
                    smart_bool.not()
                }
            }
        };

        // Check if condition involves tracked symbolic variables and add to constraint vector
        // NOTE: Avoid calling simplify() - it can hang on complex expressions!
        if self.contains_tracked_symbolic_variable(&condition_symbolic) {
            log!(
                self.state.logger.clone(),
                "Branch condition involves tracked symbolic variables, adding to constraint vector"
            );

            let path_description = if condition_concrete_bool {
                "path taken (branch executed)"
            } else {
                "path NOT taken (branch not executed)"
            };

            log!(
                self.state.logger.clone(),
                "Adding constraint to vector ({})",
                path_description
            );

            self.constraint_vector.push(condition_symbolic);
        } else {
            log!(
                self.state.logger.clone(),
                "Branch condition does not involve tracked symbolic variables, skipping"
            );
        }

        // Check if the branch target is a memory address or a constant
        match &branch_target_varnode.var {
            Var::Memory(addr) => {
                log!(
                    self.state.logger.clone(),
                    "Branch target is a specific memory address: 0x{:x}",
                    addr
                );

                // Follow concrete execution path for branch target calculation
                let branch_target_concolic = if condition_concrete_bool {
                    log!(
                        self.state.logger.clone(),
                        "Branch condition is true, branching to address 0x{:x}",
                        addr
                    );
                    let target = ConcolicVar::new_concrete_and_symbolic_int(
                        *addr,
                        BV::from_u64(self.context, *addr, 64),
                        self.context,
                    );
                    // Update RIP register with branch target (overlay-aware)
                    self.set_register_overlay_aware(0x288, target.clone(), 64)
                        .map_err(|e| e.to_string())?;
                    log!(
                        self.state.logger.clone(),
                        "Updated RIP register with branch target: 0x{:x}",
                        addr
                    );
                    target
                } else {
                    log!(
                        self.state.logger.clone(),
                        "Branch condition is false, continuing to next instruction (0x{:x})",
                        next_inst_in_map
                    );
                    // Don't update RIP - let the main loop advance to next instruction naturally
                    ConcolicVar::new_concrete_and_symbolic_int(
                        next_inst_in_map,
                        BV::from_u64(self.context, next_inst_in_map, 64),
                        self.context,
                    )
                };

                // Create or update a concolic variable for logging/tracking the branch decision
                let current_addr_hex = self
                    .current_address
                    .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                let result_var_name = format!(
                    "{}-{:02}-cbranch",
                    current_addr_hex, self.instruction_counter
                );
                self.state.create_or_update_concolic_variable_int(
                    &result_var_name,
                    branch_target_concolic.concrete.to_u64(),
                    branch_condition_concolic.symbolic,
                );
            }
            Var::Const(value) => {
                log!(
                    self.state.logger.clone(),
                    "Attempting to parse branch target constant: {:?}",
                    value
                );
                let value_string = value.to_string();
                let value_str = value_string.trim_start_matches("0x");

                let value_u64 = match u64::from_str_radix(value_str, 16) {
                    Ok(parsed) => {
                        log!(self.state.logger.clone(), "Branch target is a constant: 0x{:x}, which means this is a sub instruction of a pcode instruction.", parsed);
                        parsed
                    }
                    Err(e) => {
                        log!(
                            self.state.logger.clone(),
                            "Failed to parse constant as u64: {:?}",
                            e
                        );
                        return Err(format!("Failed to parse constant as u64: {:?}", e));
                    }
                };

                let branch_target_concolic = if condition_concrete_bool {
                    log!(self.state.logger.clone(), "Branch condition is true, and because it is a sub-instruction, the execution jumps of {:x} lines.", value_u64);
                    self.pcode_internal_lines_to_be_jumped = value_u64 as i64;
                    ConcolicVar::new_concrete_and_symbolic_int(
                        value_u64,
                        BV::from_u64(self.context, value_u64, 64),
                        self.context,
                    )
                } else {
                    log!(
                        self.state.logger.clone(),
                        "Branch condition is false, continuing to the next instruction."
                    );
                    ConcolicVar::new_concrete_and_symbolic_int(
                        next_inst_in_map,
                        BV::from_u64(self.context, next_inst_in_map, 64),
                        self.context,
                    )
                };

                let current_addr_hex = self
                    .current_address
                    .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                let result_var_name = format!(
                    "{}-{:02}-cbranch",
                    current_addr_hex, self.instruction_counter
                );
                self.state.create_or_update_concolic_variable_int(
                    &result_var_name,
                    branch_target_concolic.concrete.to_u64(),
                    branch_condition_concolic.symbolic,
                );
            }
            _ => {
                log!(
                    self.state.logger.clone(),
                    "Branch instruction doesn't handle this type of Var: {:?}",
                    branch_target_varnode.var
                );
            }
        };

        self.instruction_counter += 1;

        Ok(())
    }

    pub fn handle_call(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Call || instruction.inputs.is_empty() {
            return Err("Invalid instruction format for CALL".to_string());
        }

        // Thread scheduling checkpoint: Consider switching threads at function call
        {
            let mut tm = self.state.thread_manager.lock().unwrap();
            tm.tick_instruction();
            if let Ok(Some(new_tid)) =
                tm.maybe_switch_thread(crate::state::CheckpointType::FunctionCall)
            {
                // Thread switched - update CPU state from new thread
                if let Ok(new_thread) = tm.current_thread() {
                    let mut cpu_guard = self.state.cpu_state.lock().unwrap();
                    *cpu_guard = new_thread.cpu_state.clone();
                    drop(cpu_guard);

                    log!(
                        self.state.logger.clone(),
                        "[SCHEDULER] Switched to thread {}, updated CPU state",
                        new_tid
                    );
                }
            }
            drop(tm);
        }

        // Fetch the branch target (input0)
        // Fetch the data to be stored (treated as assembly address directly)
        log!(
            self.state.logger.clone(),
            "* Fetching data to store from instruction.input[0]"
        );
        let data_to_call_varnode = &instruction.inputs[0];
        let data_to_call_concrete = match &data_to_call_varnode.var {
            Var::Memory(value) => {
                // Convert value to u64
                log!(
                    self.state.logger.clone(),
                    "Data to store is a constant with value: 0x{:x}",
                    value
                );
                *value
            }
            _ => {
                let data_to_store_concolic = self
                    .varnode_to_concolic(data_to_call_varnode)
                    .map_err(|e| e.to_string())?;
                data_to_store_concolic.get_concrete_value()
            }
        };
        let data_to_call_symbolic = BV::from_u64(self.context, data_to_call_concrete, 64);
        let data_to_call_concolic = ConcolicVar::new_concrete_and_symbolic_int(
            data_to_call_concrete,
            data_to_call_symbolic,
            self.context,
        );

        log!(
            self.state.logger.clone(),
            "Data to call: {:x}",
            data_to_call_concrete
        );

        // Push a new function frame onto the call stack with the CORRECT target function address
        self.push_function_frame(data_to_call_concrete);

        // Update the RIP register to the branch target address (overlay-aware)
        self.set_register_overlay_aware(0x288, data_to_call_concolic, 64)?;
        // Update the instruction counter
        self.instruction_counter += 1;

        // Create or update a concolic variable for the result (CALL doesn't produce a result, but we log the branch decision)
        let current_addr_hex = self
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-call", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(
            &result_var_name,
            data_to_call_concrete,
            SymbolicVar::Int(BV::from_u64(self.context, data_to_call_concrete, 64)),
        );

        Ok(())
    }

    pub fn handle_callind(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::CallInd || instruction.inputs.is_empty() {
            return Err("Invalid instruction format for CALLIND".to_string());
        }

        // Fetch the target address from the first input
        log!(
            self.state.logger.clone(),
            "* Fetching target address from instruction.input[0]"
        );
        let target_address_concolic = self
            .varnode_to_concolic(&instruction.inputs[0])
            .map_err(|e| e.to_string())?;
        let target_address_concrete = target_address_concolic.get_concrete_value();
        let target_address_symbolic = target_address_concolic.get_symbolic_value_bv(self.context);

        log!(
            self.state.logger.clone(),
            "Target address concrete: 0x{:x}",
            target_address_concrete
        );

        // Update RIP to the target address (overlay-aware)
        let target_address_concolic = ConcolicVar::new_concrete_and_symbolic_int(
            target_address_concrete,
            target_address_symbolic,
            self.context,
        );
        self.set_register_overlay_aware(0x288, target_address_concolic.clone(), 64)?;

        // Update the instruction counter
        self.instruction_counter += 1;

        // Log the callind operation
        let current_addr_hex = format!("{:x}", self.current_address.unwrap_or(0));
        let result_var_name = format!(
            "{}-{:02}-callind",
            current_addr_hex, self.instruction_counter
        );
        self.state.create_or_update_concolic_variable_int(
            &result_var_name,
            target_address_concrete,
            target_address_concolic.symbolic,
        );

        // Update current_address to the new RIP
        self.current_address = Some(target_address_concrete);

        Ok(())
    }

    // Handle return operation
    pub fn handle_return(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Return || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for RETURN".to_string());
        }

        // Pop the function frame and clean up variables
        self.pop_function_frame();

        // Fetch the branch target (input0)
        log!(
            self.state.logger.clone(),
            "* Fetching branch target from instruction.input[0]"
        );
        let branch_target_concolic = self
            .varnode_to_concolic(&instruction.inputs[0])
            .map_err(|e| e.to_string())?;
        let branch_target_concrete = branch_target_concolic.get_concrete_value();
        let branch_target_symbolic = match branch_target_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryValue(mem_var) => SymbolicVar::Int(mem_var.symbolic),
        };
        log!(
            self.state.logger.clone(),
            "Branch target concrete : 0x{:x}",
            branch_target_concrete
        );

        let branch_target_concolic = ConcolicVar::new_concrete_and_symbolic_int(
            branch_target_concrete,
            branch_target_symbolic.to_bv(self.context),
            self.context,
        );

        // Update the RIP register to the branch target address (overlay-aware)
        self.set_register_overlay_aware(0x288, branch_target_concolic, 64)?;
        // Update the instruction counter
        self.instruction_counter += 1;

        // Create or update a concolic variable for the result (RETURN doesn't produce a result, but we log the branch decision)
        let current_addr_hex = self
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!(
            "{}-{:02}-return",
            current_addr_hex, self.instruction_counter
        );
        self.state.create_or_update_concolic_variable_int(
            &result_var_name,
            branch_target_concrete,
            branch_target_symbolic,
        );

        Ok(())
    }

    pub fn handle_load(
        &mut self,
        instruction: Inst,
        instructions_map: &BTreeMap<u64, Vec<Inst>>,
    ) -> Result<(), String> {
        if instruction.opcode != Opcode::Load || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for LOAD".to_string());
        }

        log!(
            self.state.logger.clone(),
            "* FYI, the space ID is not used during zorya execution."
        );
        log!(
            self.state.logger.clone(),
            "* Fetching pointer offset from instruction.input[1]"
        );

        let pointer_offset_concolic = self
            .varnode_to_concolic(&instruction.inputs[1])
            .map_err(|e| e.to_string())?;
        let pointer_offset_concrete = pointer_offset_concolic.get_concrete_value();
        log!(
            self.state.logger.clone(),
            "Pointer offset to be dereferenced : {:x}",
            pointer_offset_concrete
        );

        // Check if the pointer offset is concretely NULL
        if pointer_offset_concrete == 0 {
            crate::state::evaluate_z3::report_vulnerability(
                &mut self.state.logger.clone(),
                "Concrete NULL pointer dereference (LOAD)",
                self.current_address.unwrap_or(0),
                &[
                    "Opcode: LOAD",
                    "Detection method: Exploring the current path with a symbolic check on the pointer",
                    "The pointer is concretely zero — execution halted.",
                ],
            );
            process::exit(1);
        }

        // Symbolic NULL check: if the address is symbolic, ask the solver if it could be zero.
        // This detects cases where the concrete path is non-null but an alternative input
        // could make the pointer NULL (e.g. Go nil interface/map dereferences).
        // For Go struct pointers with a non-null constraint this is a no-op (cache hit).
        self.check_symbolic_null_dereference(
            &pointer_offset_concolic,
            pointer_offset_concrete,
            "LOAD",
            &instruction,
        );

        // Check for dangling pointer access (freed stack frame)
        if let Some((func_addr, frame_rsp)) =
            self.check_dangling_pointer_access(pointer_offset_concrete)
        {
            crate::state::evaluate_z3::report_vulnerability(
                &mut self.state.logger.clone(),
                "Dangling pointer access — Use-After-Free (LOAD)",
                self.current_address.unwrap_or(0),
                &[
                    "Opcode: LOAD",
                    "Detection method: Exploring the current path with a symbolic check on the pointer",
                    &format!("Accessed address: 0x{:x}", pointer_offset_concrete),
                    &format!(
                        "Memory belongs to freed stack frame from function 0x{:x} (frame RSP: 0x{:x})",
                        func_addr, frame_rsp
                    ),
                    "This is a Use-After-Free vulnerability (stack memory reuse).",
                ],
            );
        }

        // Cases covered : 'void a(void) { b(); c(); }', do the 'reinitialization'' of variables used by b() when b() finishes.
        // Implement scope management for variables
        // Clean up variables from functions that have finished
        self.cleanup_finished_function_variables(&instruction);

        // Check if the memory address has been initialized in the current scope (mainly working for C code)
        // if !self.is_address_initialized_in_current_scope(pointer_offset_concrete) {
        //     log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        //     log!(self.state.logger.clone(), "VULN: Zorya detected uninitialized memory access at address 0x{:x}", pointer_offset_concrete);
        //     log!(self.state.logger.clone(), "Execution halted due to uninitialized memory access!");
        //     log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        //     return Err(format!("Uninitialized memory access at address 0x{:x}", pointer_offset_concrete));
        // }

        // Determine the size of the data to load
        let load_size_bits = instruction
            .output
            .as_ref()
            .map(|varnode| varnode.size.to_bitvector_size())
            .unwrap_or(64); // Default to 64 bits if output size is not specified
        log!(
            self.state.logger.clone(),
            "Load size in bits: {}",
            load_size_bits
        );

        // Misalignment check
        // if pointer_offset_concrete % load_size_bytes != 0 {
        //     log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        //     log!(self.state.logger.clone(), "VULN: Zorya detected a misaligned memory access at address 0x{:x}, load size: {} bytes", pointer_offset_concrete, load_size_bytes);
        //     log!(self.state.logger.clone(), "Execution stopped due to misaligned access!");
        //     log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        //     process::exit(1);
        // }

        let mem_size = pointer_offset_concolic
            .get_symbolic_value_bv(self.context)
            .get_size();
        log!(
            self.state.logger.clone(),
            "Memory size in bits: {}",
            mem_size
        );

        // Read memory value at the pointer offset (with overlay support)
        let mut mem_value = if self.is_overlay_mode() {
            // Overlay mode: use overlay-aware reading
            log!(
                self.state.logger.clone(),
                "Reading from overlay at address 0x{:x}",
                pointer_offset_concrete
            );
            self.read_value_overlay_mode(pointer_offset_concrete, load_size_bits)?
        } else {
            // Normal mode: use standard reading
            self.state
                .memory
                .read_value(
                    pointer_offset_concrete,
                    load_size_bits,
                    &mut self.state.logger.clone(),
                )
                .map_err(|e| {
                    format!(
                        "Failed to read memory at address 0x{:x}: {:?}",
                        pointer_offset_concrete, e
                    )
                })?
        };
        let mem_value_size = mem_value.concrete.get_size();

        // For narrow memory values (<=64 bits)
        if mem_value_size <= 64 {
            if load_size_bits > mem_size {
                log!(
                    self.state.logger.clone(),
                    "Extending memory value from {} bits to {} bits",
                    mem_size,
                    load_size_bits
                );
                mem_value = ConcolicVar::new_concrete_and_symbolic_int(
                    mem_value.concrete.to_u64(),
                    mem_value.symbolic.to_bv(self.context),
                    self.context,
                );
            }
            if load_size_bits < mem_size {
                log!(
                    self.state.logger.clone(),
                    "Extracting memory value from {} bits to {} bits",
                    mem_size,
                    load_size_bits
                );
                let extracted_symbolic = mem_value
                    .symbolic
                    .to_bv(self.context)
                    .extract(load_size_bits - 1, 0);
                mem_value = ConcolicVar::new_concrete_and_symbolic_int(
                    mem_value.concrete.to_u64(),
                    extracted_symbolic,
                    self.context,
                );
            }
        }

        let mem_value_size = mem_value.concrete.get_size();
        log!(
            self.state.logger.clone(),
            "Dereferenced value: 0x{:x}, with size {:?}, and symbolic: {:?}",
            mem_value.concrete,
            mem_value_size,
            mem_value.symbolic.simplify()
        );

        // --- Handle jump table access versus regular LOAD ---
        let dereferenced_concolic = if self.inside_jump_table {
            // ---- Jump Table Branch ----
            log!(self.state.logger.clone(), "Handling jump table access.");
            self.inside_jump_table = false; // Reset jump table flag

            // Lookup the jump table corresponding to the pointer offset.
            let jump_table = {
                let tables = &self.state.jump_tables;
                tables
                    .values()
                    .find(|table| table.table_address == pointer_offset_concrete)
                    .cloned()
                    .ok_or_else(|| {
                        "Pointer offset does not match any known jump table.".to_string()
                    })?
            };
            log!(self.state.logger.clone(), "Matched jump table.");

            // Resolve the jump table index (this function is assumed to exist).
            let index_bv = self
                .get_jump_table_index(self.context, instructions_map)
                .map_err(|e| format!("Failed to resolve jump table index: {}", e))?;
            log!(self.state.logger.clone(), "Resolved jump table index.");

            // Build a cascading ITE (if-then-else) to select the jump destination.
            let mut result = BV::from_u64(self.context, 0, 64);
            for (case_index, entry) in jump_table.cases.iter().enumerate() {
                let condition = index_bv._eq(&BV::from_u64(self.context, case_index as u64, 64));
                let destination_bv = BV::from_u64(self.context, entry.destination, 64);
                result = condition.ite(&destination_bv, &result);
            }

            // Now, update the symbolic portion of the loaded memory.
            if mem_value_size > 64 {
                let full_sym: BV = if mem_value.symbolic.get_size() < load_size_bits {
                    mem_value
                        .symbolic
                        .to_bv(self.context)
                        .zero_ext(load_size_bits - mem_value.symbolic.get_size())
                } else {
                    mem_value.symbolic.to_bv(self.context)
                };
                let full_sym_size = full_sym.get_size();
                let num_chunks = load_size_bits.div_ceil(64) as usize;
                let mut large_sym = Vec::with_capacity(num_chunks);
                for i in 0..num_chunks {
                    let low = i * 64;
                    let high = std::cmp::min(full_sym_size, low as u32 + 64) - 1;
                    if high < low as u32 {
                        return Err(format!(
                            "[ERROR] Invalid BV extraction range: {} to {}, effective symbolic size: {}",
                            low, high, full_sym_size
                        ));
                    }
                    large_sym.push(full_sym.extract(high, low as u32));
                }
                ConcolicVar::new_concrete_and_symbolic_large_int(
                    mem_value.concrete.to_largeint(),
                    large_sym,
                    self.context,
                )
            } else {
                ConcolicVar::new_concrete_and_symbolic_int(
                    mem_value.concrete.to_u64(),
                    mem_value.symbolic.clone().to_bv(self.context),
                    self.context,
                )
            }
        } else {
            // ---- Regular LOAD Branch ----
            if mem_value_size > 64 {
                let full_sym: BV = if mem_value.symbolic.get_size() < load_size_bits {
                    mem_value
                        .symbolic
                        .to_bv(self.context)
                        .zero_ext(load_size_bits - mem_value.symbolic.get_size())
                } else {
                    mem_value.symbolic.to_bv(self.context)
                };
                let full_sym_size = full_sym.get_size();
                let num_chunks = load_size_bits.div_ceil(64) as usize;
                let mut large_sym = Vec::with_capacity(num_chunks);
                for i in 0..num_chunks {
                    let low = i * 64;
                    let high = std::cmp::min(full_sym_size, low as u32 + 64) - 1;
                    if high < low as u32 {
                        return Err(format!(
                            "[ERROR] Invalid BV extraction range: {} to {}, effective symbolic size: {}",
                            low, high, full_sym_size
                        ));
                    }
                    large_sym.push(full_sym.extract(high, low as u32));
                }
                ConcolicVar::new_concrete_and_symbolic_large_int(
                    mem_value.concrete.to_largeint(),
                    large_sym,
                    self.context,
                )
            } else {
                ConcolicVar::new_concrete_and_symbolic_int(
                    mem_value.concrete.to_u64(),
                    mem_value.symbolic.clone().to_bv(self.context),
                    self.context,
                )
            }
        };

        // --- End of dereferenced value construction ---

        // Write the loaded value into the output.
        if let Some(output_varnode) = instruction.output.as_ref() {
            match &output_varnode.var {
                Var::Unique(id) => {
                    log!(
                        self.state.logger.clone(),
                        "Output is a Unique type with ID: 0x{:x}",
                        id
                    );
                    let unique_name = format!("Unique(0x{:x})", id);
                    self.unique_variables
                        .insert(unique_name.clone(), dereferenced_concolic.clone());
                    log!(
                        self.state.logger.clone(),
                        "Updated Unique(0x{:x}) with concrete value 0x{:x} and size {:?}",
                        id,
                        dereferenced_concolic.concrete.to_u64(),
                        dereferenced_concolic.concrete.get_size()
                    );
                }
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");

                    // Normalize SIMD register offsets (XMM/YMM/ZMM) using the CPU state helper
                    let write_offset = {
                        let cpu_state_guard = self.state.cpu_state.lock().unwrap();
                        cpu_state_guard.map_simd_virtual_offset(*offset)
                    };

                    // Use overlay-aware register write (writes to overlay if active, otherwise base)
                    match self.set_register_overlay_aware(
                        write_offset,
                        dereferenced_concolic.clone(),
                        load_size_bits,
                    ) {
                        Ok(_) => {
                            log!(
                                self.state.logger.clone(),
                                "Updated register at offset 0x{:x} with value 0x{:x}",
                                write_offset,
                                dereferenced_concolic.concrete.to_u64()
                            );
                        }
                        Err(e) => {
                            let error_msg = format!(
                                "Failed to update register at offset 0x{:x}: {:?}",
                                write_offset, e
                            );
                            log!(self.state.logger.clone(), "{}", error_msg);
                            return Err(error_msg);
                        }
                    }
                }
                _ => {
                    let error_msg = "Output type is unsupported".to_string();
                    log!(self.state.logger.clone(), "{}", error_msg);
                    return Err(error_msg);
                }
            }
        } else {
            return Err("No output variable specified for LOAD instruction".to_string());
        }

        // For debugging, create a named concolic variable for the result.
        let current_addr_hex = self
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-load", current_addr_hex, self.instruction_counter);
        if mem_value_size > 64 {
            self.state.create_or_update_concolic_variable_largeint(
                &result_var_name,
                mem_value.concrete.to_largeint(),
                SymbolicVar::LargeInt(mem_value.symbolic.clone().to_largebv()),
            );
        } else {
            self.state.create_or_update_concolic_variable_int(
                &result_var_name,
                mem_value.concrete.to_u64(),
                SymbolicVar::Int(mem_value.symbolic.clone().to_bv(self.context)),
            );
        }
        Ok(())
    }

    pub fn get_jump_table_index(
        &mut self,
        context: &'ctx z3::Context,
        instructions_map: &BTreeMap<u64, Vec<Inst>>,
    ) -> Result<BV<'ctx>, String> {
        // Traverse the instruction map to find the defining COPY, INT_MULT, and INT_ADD instructions
        let mut base_bv = None; // Base register BV (from COPY)
        let mut scale_bv = None; // Scale factor BV (from INT_MULT)
        let mut index_bv = None; // Final index BV (from INT_ADD)

        // Start from the current instruction and move backward
        for (_addr, insts) in instructions_map.iter().rev() {
            for inst in insts.iter().rev() {
                match inst.opcode {
                    Opcode::Copy => {
                        if base_bv.is_none() {
                            // Delegate to `handle_copy` to extract the base register
                            self.handle_copy(inst.clone())?;
                            base_bv = Some(
                                self.varnode_to_concolic(inst.output.as_ref().unwrap())?
                                    .get_symbolic_value_bv(context),
                            );
                        }
                    }
                    Opcode::IntMult => {
                        if scale_bv.is_none() {
                            // Delegate to `handle_int_mult` to extract the scaled value
                            executor_int::handle_int_mult(self, inst.clone())?;
                            scale_bv = Some(
                                self.varnode_to_concolic(inst.output.as_ref().unwrap())?
                                    .get_symbolic_value_bv(context),
                            );
                        }
                    }
                    Opcode::IntAdd => {
                        if index_bv.is_none() {
                            // Delegate to `handle_int_add` to calculate the final index
                            executor_int::handle_int_add(self, inst.clone())?;
                            index_bv = Some(
                                self.varnode_to_concolic(inst.output.as_ref().unwrap())?
                                    .get_symbolic_value_bv(context),
                            );
                            break; // No need to continue once the final index is resolved
                        }
                    }
                    _ => {}
                }

                // Stop if we have resolved all components
                if base_bv.is_some() && scale_bv.is_some() && index_bv.is_some() {
                    break;
                }
            }
        }

        // Combine the resolved components into the final index
        if let (Some(base), Some(scale), Some(index)) = (base_bv, scale_bv, index_bv) {
            log!(
                self.state.logger.clone(),
                "Base: {:?}, Scale: {:?}, Index: {:?}",
                base,
                scale,
                index
            );
            Ok(index)
        } else {
            Err("Failed to resolve jump table index: Missing one or more components.".to_string())
        }
    }

    // Handle STORE operation with chunked storage for LargeInt values
    pub fn handle_store(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format
        if instruction.opcode != Opcode::Store || instruction.inputs.len() != 3 {
            return Err("Invalid instruction format for STORE".to_string());
        }

        // Fetch the pointer offset
        log!(
            self.state.logger.clone(),
            "* Fetching pointer offset from instruction.input[1]"
        );
        let pointer_offset_var = self
            .varnode_to_concolic(&instruction.inputs[1])
            .map_err(|e| e.to_string())?;
        let pointer_offset_concrete = pointer_offset_var.get_concrete_value();
        log!(
            self.state.logger.clone(),
            "Pointer offset concrete: {:x}",
            pointer_offset_concrete
        );

        // Mark the memory address as initialized
        self.initialiazed_var
            .insert(pointer_offset_concrete, self.current_address.unwrap_or(0));
        log!(
            self.state.logger.clone(),
            "Marked address 0x{:x} as initialized",
            pointer_offset_concrete
        );

        // Validate pointer to prevent null dereference (concrete check)
        if pointer_offset_concrete == 0 {
            crate::state::evaluate_z3::report_vulnerability(
                &mut self.state.logger.clone(),
                "Concrete NULL pointer dereference (STORE)",
                self.current_address.unwrap_or(0),
                &[
                    "Opcode: STORE",
                    "Detection method: Exploring the current path with a symbolic check on the pointer",
                    "The pointer is concretely zero — execution halted.",
                ],
            );
            process::exit(1);
        }

        // Symbolic NULL check: detect if the store address could be NULL on an alternative path.
        // For Go struct pointers with a non-null constraint this is a no-op (cache hit).
        self.check_symbolic_null_dereference(
            &pointer_offset_var,
            pointer_offset_concrete,
            "STORE",
            &instruction,
        );

        // Check for dangling pointer access (freed stack frame)
        if let Some((func_addr, frame_rsp)) =
            self.check_dangling_pointer_access(pointer_offset_concrete)
        {
            crate::state::evaluate_z3::report_vulnerability(
                &mut self.state.logger.clone(),
                "Dangling pointer write — Use-After-Free (STORE)",
                self.current_address.unwrap_or(0),
                &[
                    "Opcode: STORE",
                    "Detection method: Exploring the current path with a symbolic check on the pointer",
                    &format!("Written address: 0x{:x}", pointer_offset_concrete),
                    &format!(
                        "Memory belongs to freed stack frame from function 0x{:x} (frame RSP: 0x{:x})",
                        func_addr, frame_rsp
                    ),
                    "This is a Use-After-Free vulnerability (stack memory reuse).",
                ],
            );
        }

        // Fetch the data to be stored
        log!(
            self.state.logger.clone(),
            "* Fetching data to store from instruction.input[2]"
        );
        let data_to_store_var = &instruction.inputs[2];
        let data_to_store_concolic = self
            .varnode_to_concolic(data_to_store_var)
            .map_err(|e| e.to_string())?;

        // Get the full concrete value (preserving all chunks)
        let full_concrete_value = data_to_store_concolic.get_full_concrete_value();
        let data_to_store_symbolic = data_to_store_concolic.get_symbolic_value_bv(self.context);

        // Determine the size of the data to store
        let data_size_bits = data_to_store_var.size.to_bitvector_size();
        log!(
            self.state.logger.clone(),
            "Data size in bits: {}",
            data_size_bits
        );

        // Ensure symbolic value size matches data size
        let symbolic_size = data_to_store_symbolic.get_size();
        if symbolic_size != data_size_bits {
            return Err(format!(
                "Symbolic size {} does not match data size {}",
                symbolic_size, data_size_bits
            ));
        }

        // Handle storage based on concrete value type
        match &full_concrete_value {
            ConcreteVar::LargeInt(chunks) => {
                log!(
                    self.state.logger.clone(),
                    "Storing LargeInt with {} chunks: {:?}",
                    chunks.len(),
                    chunks
                );

                // Store each chunk at consecutive 8-byte addresses
                for (i, &chunk) in chunks.iter().enumerate() {
                    let chunk_addr = pointer_offset_concrete + (i as u64 * 8);

                    // Extract the appropriate part of the symbolic value for this chunk
                    let chunk_symbolic = if data_size_bits <= 64 {
                        // For single chunk data, use the full symbolic value
                        data_to_store_symbolic.clone()
                    } else {
                        // For multi-chunk data, extract the appropriate 64-bit slice
                        // IMPORTANT: Match the chunk order with the symbolic concatenation
                        // Symbolic: (concat indices_R8!258 indices_len_R9!259)
                        // This means: [high 64 bits = indices_R8!258, low 64 bits = indices_len_R9!259]
                        // LargeInt: [chunk0 = ptr, chunk1 = len]
                        // So: chunk0 (ptr) should get high bits, chunk1 (len) should get low bits

                        if i == 0 {
                            // Chunk 0 (ptr) = high 64 bits (127:64)
                            data_to_store_symbolic.extract(127, 64)
                        } else if i == 1 {
                            // Chunk 1 (len) = low 64 bits (63:0)
                            data_to_store_symbolic.extract(63, 0)
                        } else {
                            // Additional chunks beyond 128 bits
                            BV::from_u64(self.context, 0, 64)
                        }
                    };

                    // Create individual MemoryValue for each chunk
                    let chunk_mem_value = MemoryValue {
                        concrete: chunk,
                        symbolic: chunk_symbolic.clone(),
                        size: 64, // Each chunk is 64 bits
                    };

                    log!(
                        self.state.logger.clone(),
                        "Creating chunk {} MemoryValue: concrete=0x{:x}, symbolic={:?}, size=64",
                        i,
                        chunk,
                        chunk_symbolic.simplify()
                    );

                    // Write the chunk to memory (with overlay support)
                    let write_result = if self.is_overlay_mode() {
                        self.write_value_overlay_mode(chunk_addr, &chunk_mem_value)
                    } else {
                        self.state.memory.write_value(chunk_addr, &chunk_mem_value)
                    };
                    match write_result {
                        Ok(_) => {
                            log!(
                                self.state.logger.clone(),
                                "Stored chunk {} (0x{:x}) at address 0x{:x}",
                                i,
                                chunk,
                                chunk_addr
                            );
                        }
                        Err(e) => {
                            let error_msg = format!(
                                "Failed to write chunk {} to memory at address 0x{:x}: {:?}",
                                i, chunk_addr, e
                            );
                            log!(self.state.logger.clone(), "{}", error_msg);
                            return Err(error_msg);
                        }
                    }

                    // Mark each chunk address as initialized
                    self.initialiazed_var
                        .insert(chunk_addr, self.current_address.unwrap_or(0));
                }

                // Log the complete operation
                log!(
                    self.state.logger.clone(),
                    "Stored complete LargeInt value starting at 0x{:x} ({} chunks)",
                    pointer_offset_concrete,
                    chunks.len()
                );
            }
            ConcreteVar::Int(value) => {
                // Handle single values normally
                // Truncate concrete value to match the size in bits
                let truncated_value = if data_size_bits < 64 {
                    let mask = (1u64 << data_size_bits) - 1;
                    value & mask
                } else {
                    *value
                };

                // Only call Z3 simplify() on truly symbolic expressions.
                // For concrete-only BVs (the common case: no tracked variable
                // involved) simplify() is a no-op but still walks the AST.
                // Skipping it for numerals avoids an O(tree_size) traversal on
                // every store — the single biggest per-store cost.
                let store_symbolic = if data_to_store_symbolic.as_u64().is_some() {
                    // Leaf BV (numeral) — already canonical, skip simplify.
                    data_to_store_symbolic.clone()
                } else {
                    // Complex symbolic expression — simplify to prevent
                    // unbounded tree growth through store→load→extract→concat
                    // cycles.
                    data_to_store_symbolic.simplify()
                };

                let mem_value = MemoryValue {
                    concrete: truncated_value,
                    symbolic: store_symbolic,
                    size: data_size_bits,
                };

                log!(
                    self.state.logger.clone(),
                    "Creating single MemoryValue: concrete=0x{:x}, symbolic={:?}, size={}",
                    mem_value.concrete,
                    mem_value.symbolic,
                    mem_value.size
                );

                // Write the single value to memory (with overlay support)
                let write_result = if self.is_overlay_mode() {
                    self.write_value_overlay_mode(pointer_offset_concrete, &mem_value)
                } else {
                    self.state
                        .memory
                        .write_value(pointer_offset_concrete, &mem_value)
                };
                match write_result {
                    Ok(_) => {
                        log!(
                            self.state.logger.clone(),
                            "Stored single value 0x{:x} to memory at address 0x{:x}",
                            truncated_value,
                            pointer_offset_concrete
                        );
                    }
                    Err(e) => {
                        let error_msg = format!(
                            "Failed to write to memory at address 0x{:x}: {:?}",
                            pointer_offset_concrete, e
                        );
                        log!(self.state.logger.clone(), "{}", error_msg);
                        return Err(error_msg);
                    }
                }
            }
            _ => {
                return Err("Unsupported concrete variable type in STORE".to_string());
            }
        }

        // Verification: Read back the stored value(s) to verify correctness.
        // Only compiled in debug builds — in release this block is a no-op.
        // Previously this ran unconditionally on every store, doubling memory I/O
        // (one write + one full read + one Z3 BV construction per store).
        #[cfg(debug_assertions)]
        match &full_concrete_value {
            ConcreteVar::LargeInt(chunks) => {
                for (i, &expected_chunk) in chunks.iter().enumerate() {
                    let chunk_addr = pointer_offset_concrete + (i as u64 * 8);
                    let read_result = if self.is_overlay_mode() {
                        self.read_value_overlay_mode(chunk_addr, 64)
                            .map_err(MemoryError::Other)
                    } else {
                        self.state
                            .memory
                            .read_value(chunk_addr, 64, &mut self.state.logger.clone())
                    };
                    match read_result {
                        Ok(stored_value) => {
                            let stored_concrete_value = match stored_value.concrete {
                                ConcreteVar::Int(val) => val,
                                ConcreteVar::LargeInt(ref values) => {
                                    values.first().copied().unwrap_or(0)
                                }
                                _ => 0,
                            };
                            log!(
                                self.state.logger.clone(),
                                "Verified chunk {} at 0x{:x}: stored=0x{:x}, expected=0x{:x}",
                                i,
                                chunk_addr,
                                stored_concrete_value,
                                expected_chunk
                            );
                            if stored_concrete_value != expected_chunk {
                                return Err(format!(
                                    "Chunk {} verification failed: expected 0x{:x}, got 0x{:x}",
                                    i, expected_chunk, stored_concrete_value
                                ));
                            }
                        }
                        Err(e) => {
                            return Err(format!(
                                "Failed to verify chunk {} at address 0x{:x}: {:?}",
                                i, chunk_addr, e
                            ));
                        }
                    }
                }
            }
            ConcreteVar::Int(expected_value) => {
                let truncated_expected = if data_size_bits < 64 {
                    let mask = (1u64 << data_size_bits) - 1;
                    expected_value & mask
                } else {
                    *expected_value
                };
                let read_result = if self.is_overlay_mode() {
                    self.read_value_overlay_mode(pointer_offset_concrete, data_size_bits)
                        .map_err(MemoryError::Other)
                } else {
                    self.state.memory.read_value(
                        pointer_offset_concrete,
                        data_size_bits,
                        &mut self.state.logger.clone(),
                    )
                };
                match read_result {
                    Ok(stored_value) => {
                        let stored_concrete_value = match stored_value.concrete {
                            ConcreteVar::Int(val) => val,
                            ConcreteVar::LargeInt(ref values) => {
                                values.first().copied().unwrap_or(0)
                            }
                            _ => 0,
                        };
                        log!(
                            self.state.logger.clone(),
                            "Verified single value at 0x{:x}: stored=0x{:x}, expected=0x{:x}",
                            pointer_offset_concrete,
                            stored_concrete_value,
                            truncated_expected
                        );
                        if stored_concrete_value != truncated_expected {
                            return Err(format!(
                                "Single value verification failed: expected 0x{:x}, got 0x{:x}",
                                truncated_expected, stored_concrete_value
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(format!(
                            "Failed to verify single value at address 0x{:x}: {:?}",
                            pointer_offset_concrete, e
                        ));
                    }
                }
            }
            _ => {}
        }

        // Checks if the used variable has been initialized in the current scope (C code vulnerability)
        // TODO: handle more complex cases in C code by checking RSP register (that both CALL and RET use)
        // Mark the memory address as initialized
        self.initialiazed_var
            .insert(pointer_offset_concrete, self.current_address.unwrap_or(0));
        log!(
            self.state.logger.clone(),
            "Marked address 0x{:x} as initialized",
            pointer_offset_concrete
        );

        // Add the address to the current function frame's local variables
        // if let Some(current_frame) = self.state.call_stack.last_mut() {
        //     current_frame.local_variables.insert(address_str.clone());
        //     log!(self.state.logger.clone(), "Added address 0x{:x} to current function frame's local variables", pointer_offset_concrete);
        // } else {
        //     log!(self.state.logger.clone(), "No function frame found at address 0x{:x}", pointer_offset_concrete);
        // }

        // Update CPU register if the address maps to one
        // Check if the address corresponds to a register
        let is_register = {
            let cpu_state_guard = self.state.cpu_state.lock().unwrap();
            cpu_state_guard
                .get_register_by_offset(pointer_offset_concrete, data_size_bits)
                .is_some()
        };

        if is_register {
            // Use overlay-aware register write (writes to overlay if active, otherwise base)
            match self.set_register_overlay_aware(
                pointer_offset_concrete,
                data_to_store_concolic.to_concolic_var().unwrap(),
                data_size_bits,
            ) {
                Ok(_) => {
                    log!(
                        self.state.logger.clone(),
                        "Updated register at offset 0x{:x} with symbolic part {:?}",
                        pointer_offset_concrete,
                        data_to_store_symbolic.simplify()
                    );
                }
                Err(e) => {
                    let error_msg = format!(
                        "Failed to update register at offset 0x{:x}: {}",
                        pointer_offset_concrete, e
                    );
                    log!(self.state.logger.clone(), "{}", error_msg);
                    return Err(error_msg);
                }
            }
        }

        // Record the operation for traceability
        let current_addr_hex = self
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));

        match &full_concrete_value {
            ConcreteVar::LargeInt(chunks) => {
                // Create traceability entries for each chunk
                for (i, &chunk) in chunks.iter().enumerate() {
                    let chunk_var_name = format!(
                        "{}-{:02}-store-chunk-{}",
                        current_addr_hex, self.instruction_counter, i
                    );
                    let chunk_symbolic = if data_size_bits <= 64 {
                        data_to_store_symbolic.clone()
                    } else {
                        let start_bit = i as u32 * 64;
                        let end_bit = std::cmp::min(start_bit + 64, data_size_bits);
                        if start_bit >= data_size_bits {
                            BV::from_u64(self.context, 0, 64)
                        } else {
                            data_to_store_symbolic.extract(end_bit - 1, start_bit)
                        }
                    };

                    self.state.create_or_update_concolic_variable_int(
                        &chunk_var_name,
                        chunk,
                        SymbolicVar::Int(chunk_symbolic),
                    );
                }
            }
            ConcreteVar::Int(value) => {
                let result_var_name =
                    format!("{}-{:02}-store", current_addr_hex, self.instruction_counter);
                self.state.create_or_update_concolic_variable_int(
                    &result_var_name,
                    *value,
                    SymbolicVar::Int(data_to_store_symbolic.clone()),
                );
            }
            _ => {}
        }

        Ok(())
    }

    pub fn handle_copy(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Copy || instruction.inputs.len() != 1 {
            return Err("[ERROR] Invalid instruction format for COPY".to_string());
        }

        let output_varnode = instruction.output.as_ref().unwrap();
        let output_size_bits = output_varnode.size.to_bitvector_size();

        log!(
            self.state.logger.clone(),
            "Output size in bits: {}",
            output_size_bits
        );

        // Fetch the source explicitly
        log!(
            self.state.logger.clone(),
            "* Fetching source from instruction.input[0]"
        );
        let source_concolic = self
            .varnode_to_concolic(&instruction.inputs[0])?
            .to_concolic_var()
            .unwrap();

        let new_symbolic = match &source_concolic.symbolic {
            SymbolicVar::LargeInt(bv_vec) => {
                if output_size_bits <= 64 {
                    if bv_vec.is_empty() {
                        return Err("[ERROR] Empty LargeInt vector in COPY".to_string());
                    }
                    let first_bv = bv_vec[0].clone(); // clone to avoid partial move
                    SymbolicVar::Int(first_bv.extract(output_size_bits - 1, 0))
                } else {
                    // Recombine only the necessary number of bits
                    let mut remaining_bits = output_size_bits;
                    let mut result_bv_opt = None;

                    for bv in bv_vec.iter().rev() {
                        if remaining_bits == 0 {
                            break;
                        }
                        let size = bv.get_size().min(remaining_bits);
                        let extracted = bv.extract(size - 1, 0);

                        result_bv_opt = Some(match result_bv_opt {
                            Some(prev) => extracted.concat(&prev),
                            None => extracted,
                        });

                        remaining_bits -= size;
                    }

                    match result_bv_opt {
                        Some(bv) => SymbolicVar::Int(bv),
                        None => {
                            return Err(
                                "[ERROR] Could not reconstruct symbolic from LargeInt".to_string()
                            )
                        }
                    }
                }
            }
            SymbolicVar::Int(bv) => {
                if bv.get_size() > output_size_bits {
                    SymbolicVar::Int(bv.extract(output_size_bits - 1, 0).simplify())
                } else if bv.get_size() < output_size_bits {
                    SymbolicVar::Int(bv.zero_ext(output_size_bits - bv.get_size()).simplify())
                } else {
                    SymbolicVar::Int(bv.clone())
                }
            }
            SymbolicVar::Bool(b) => {
                let bv_int = b.ite(
                    &BV::from_u64(self.context, 1, output_size_bits),
                    &BV::from_u64(self.context, 0, output_size_bits),
                );
                SymbolicVar::Int(bv_int)
            }
            _ => return Err("[ERROR] Unsupported symbolic type in COPY".to_string()),
        };

        // Handle concrete copy
        let num_chunks = output_size_bits.div_ceil(64) as usize;
        let mut concrete_chunks = vec![0u64; num_chunks];

        match &source_concolic.concrete {
            ConcreteVar::LargeInt(values) => {
                for (i, &val) in values.iter().enumerate().take(num_chunks) {
                    concrete_chunks[i] = val;
                }
            }
            ConcreteVar::Int(val) => concrete_chunks[0] = *val,
            ConcreteVar::Bool(b_val) => concrete_chunks[0] = if *b_val { 1u64 } else { 0u64 },
            _ => return Err("[ERROR] Unsupported concrete type in COPY".to_string()),
        }

        // Construct final ConcolicVar
        let new_concolic_var = if output_size_bits > 64 {
            // Turn symbolic Int into LargeInt representation
            let bv = match &new_symbolic {
                SymbolicVar::Int(bv) => bv.clone(),
                _ => return Err("[ERROR] Unexpected symbolic type for LargeInt copy".to_string()),
            };

            let mut bv_vec = Vec::new();
            let mut bits_left = bv.get_size();
            let mut curr_bv = bv;

            while bits_left > 64 {
                let chunk = curr_bv.extract(63, 0);
                bv_vec.push(chunk);
                curr_bv = curr_bv.extract(bits_left - 1, 64);
                bits_left -= 64;
            }

            bv_vec.push(curr_bv);

            ConcolicVar {
                concrete: ConcreteVar::LargeInt(concrete_chunks.clone()),
                symbolic: SymbolicVar::LargeInt(bv_vec),
                ctx: self.context,
            }
        } else {
            ConcolicVar {
                concrete: ConcreteVar::Int(concrete_chunks[0]),
                symbolic: match &new_symbolic {
                    SymbolicVar::Int(bv) => SymbolicVar::Int(bv.clone()),
                    SymbolicVar::LargeInt(bv_vec) => {
                        if bv_vec.is_empty() {
                            return Err(
                                "[ERROR] Empty LargeInt symbolic in COPY (small case)".to_string()
                            );
                        }
                        SymbolicVar::Int(bv_vec[0].clone())
                    }
                    SymbolicVar::Bool(b) => {
                        let bv_int = b.ite(
                            &BV::from_u64(self.context, 1, output_size_bits),
                            &BV::from_u64(self.context, 0, output_size_bits),
                        );
                        SymbolicVar::Int(bv_int)
                    }
                    _ => return Err("[ERROR] Unexpected symbolic type for small COPY".to_string()),
                },
                ctx: self.context,
            }
        };

        // Write to the target
        match &output_varnode.var {
            Var::Unique(id) => {
                self.unique_variables
                    .insert(format!("Unique(0x{:x})", id), new_concolic_var);
            }
            Var::Register(offset, _) => {
                // Use overlay-aware register write (writes to overlay if active, otherwise base)
                self.set_register_overlay_aware(*offset, new_concolic_var, output_size_bits)?;
            }
            Var::Memory(addr) => {
                let mem_value = MemoryValue {
                    concrete: concrete_chunks[0],
                    symbolic: new_symbolic.to_bv(self.context),
                    size: output_size_bits,
                };
                self.state
                    .memory
                    .write_value(*addr, &mem_value)
                    .map_err(|e| e.to_string())?;
            }
            _ => return Err("[ERROR] Unsupported output type in COPY".to_string()),
        }

        Ok(())
    }

    // The function to handle POPCOUNT instruction
    pub fn handle_popcount(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::PopCount
            || instruction.inputs.len() != 1
            || instruction.output.is_none()
        {
            return Err("Invalid instruction format for POPCOUNT".to_string());
        }

        log!(
            self.state.logger.clone(),
            "* Fetching instruction.input[0] for POPCOUNT"
        );
        let input_var = self
            .varnode_to_concolic(&instruction.inputs[0])
            .map_err(|e| {
                log!(
                    self.state.logger.clone(),
                    "Error converting varnode to concolic: {}",
                    e
                );
                e.to_string()
            })?;

        let output_size_bits = instruction
            .output
            .as_ref()
            .unwrap()
            .size
            .to_bitvector_size();

        // Use the input operand width for correctness (e.g., popcount after AND 0xff)
        let input_size_bits = instruction.inputs[0].size.to_bitvector_size();

        // Concrete popcount respecting the input bit width
        let mask = if input_size_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << input_size_bits) - 1
        };
        let result_concrete = (input_var.get_concrete_value() & mask).count_ones();

        let symbolic_input = input_var.to_concolic_var().unwrap().symbolic;
        let result_symbolic = match symbolic_input {
            SymbolicVar::Int(bv) => {
                // Exact popcount over the input width; cap very large widths for solver sanity
                let width = bv.get_size().min(input_size_bits).min(256);
                let sum_width = width.clamp(1u32, 64);
                let mut sum = BV::from_u64(self.context, 0, sum_width);
                for i in 0..width {
                    let bit1 = bv.extract(i, i);
                    // zero_ext expects the number of bits to add, not the target size
                    let bit = if sum_width > 1 {
                        bit1.zero_ext(sum_width - 1)
                    } else {
                        bit1
                    };
                    sum = sum.bvadd(&bit);
                }
                // Fit to the declared output width (ensure valid width >=1)
                let out_w = if output_size_bits == 0 {
                    1
                } else {
                    output_size_bits
                };
                if sum.get_size() > out_w {
                    sum.extract(out_w - 1, 0)
                } else if sum.get_size() < out_w {
                    sum.zero_ext(out_w - sum.get_size())
                } else {
                    sum
                }
            }
            _ => {
                log!(
                    self.state.logger.clone(),
                    "Warning: Unsupported symbolic type for POPCOUNT"
                );
                BV::from_u64(self.context, 0, output_size_bits)
            }
        };

        let popcount_result = ConcolicVar::new_concrete_and_symbolic_int(
            result_concrete as u64,
            result_symbolic,
            self.context,
        );

        self.handle_output(instruction.output.as_ref(), popcount_result.clone())?;

        let current_addr_hex = self
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!(
            "{}-{:02}-popcount",
            current_addr_hex, self.instruction_counter
        );
        self.state.create_or_update_concolic_variable_int(
            &result_var_name,
            popcount_result.concrete.to_u64(),
            popcount_result.symbolic,
        );

        Ok(())
    }

    // Handle the SUBPIECE operation
    pub fn handle_subpiece(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::SubPiece || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for SUBPIECE".to_string());
        }

        log!(
            self.state.logger.clone(),
            "* Fetching source data from instruction.input[0] for SUBPIECE"
        );

        let source_concolic = self
            .varnode_to_concolic(&instruction.inputs[0])
            .map_err(|e| format!("Failed to fetch source data: {}", e))?
            .to_concolic_var()
            .unwrap();
        let source_concrete = &source_concolic.concrete;
        let source_symbolic = &source_concolic.symbolic;

        log!(
            self.state.logger.clone(),
            "* Fetching truncation offset from instruction.input[1] for SUBPIECE"
        );

        // Parse the truncation offset (in bytes) from the constant input.
        let offset_bytes = if let Var::Const(value) = &instruction.inputs[1].var {
            u32::from_str_radix(value.trim_start_matches("0x"), 16)
                .map_err(|e| format!("Failed to parse offset value: {}", e))?
        } else {
            return Err("SUBPIECE expects a constant for input1".to_string());
        };

        let output_size_bits = instruction
            .output
            .as_ref()
            .unwrap()
            .size
            .to_bitvector_size();
        let bit_offset = offset_bytes * 8; // Convert byte offset to bits

        log!(
            self.state.logger.clone(),
            "SUBPIECE: extracting {} bits starting at byte offset {} (bit offset {})",
            output_size_bits,
            offset_bytes,
            bit_offset
        );

        // --- Handle Concrete Value Extraction ---
        let truncated_concrete = match source_concrete {
            ConcreteVar::Int(value) => {
                Self::subpiece_concrete_int(*value, bit_offset, output_size_bits)
            }
            ConcreteVar::LargeInt(values) => {
                Self::subpiece_concrete_largeint(values, bit_offset, output_size_bits)
            }
            _ => return Err("Unsupported concrete variable type in SUBPIECE".to_string()),
        };

        // --- Handle Symbolic Value Extraction ---
        let truncated_symbolic = match source_symbolic {
            SymbolicVar::Int(bv) => {
                let safe_bv = Self::subpiece_bv(self.context, bv, bit_offset, output_size_bits);
                if output_size_bits <= 64 {
                    SymbolicVar::Int(safe_bv)
                } else {
                    // Split into chunks for large outputs
                    let chunk_count = output_size_bits.div_ceil(64);
                    let splitted =
                        Self::split_largeint(self.context, &safe_bv, chunk_count as usize);
                    SymbolicVar::LargeInt(splitted)
                }
            }
            SymbolicVar::LargeInt(bv_vec) => {
                let combined = Self::combine_largeint(self.context, bv_vec);
                let safe_bv =
                    Self::subpiece_bv(self.context, &combined, bit_offset, output_size_bits);

                if output_size_bits <= 64 {
                    SymbolicVar::Int(safe_bv)
                } else {
                    let chunk_count = output_size_bits.div_ceil(64);
                    let splitted =
                        Self::split_largeint(self.context, &safe_bv, chunk_count as usize);
                    SymbolicVar::LargeInt(splitted)
                }
            }
            _ => return Err("Unsupported symbolic variable type in SUBPIECE".to_string()),
        };

        // Create the result ConcolicVar from the truncated concrete and symbolic parts.
        let result_value = ConcolicVar {
            concrete: truncated_concrete,
            symbolic: truncated_symbolic,
            ctx: self.context,
        };

        log!(
            self.state.logger.clone(),
            "SUBPIECE result: concrete={:?}, output_size_bits={}",
            result_value.concrete,
            output_size_bits
        );

        // Output the result to the destination.
        self.handle_output(instruction.output.as_ref(), result_value.clone())?;

        // Create or update a named concolic variable for debugging/tracking.
        let current_addr_hex = self
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!(
            "{}-{:02}-subpiece",
            current_addr_hex, self.instruction_counter
        );

        // Choose appropriate storage method based on output size
        if output_size_bits > 64 {
            self.state.create_or_update_concolic_variable_largeint(
                &result_var_name,
                match result_value.concrete {
                    ConcreteVar::LargeInt(ref vec) => vec.clone(),
                    ConcreteVar::Int(val) => vec![val],
                    _ => vec![result_value.concrete.to_u64()],
                },
                result_value.symbolic.clone(),
            );
        } else {
            self.state.create_or_update_concolic_variable_int(
                &result_var_name,
                result_value.concrete.to_u64(),
                result_value.symbolic.clone(),
            );
        }

        log!(
            self.state.logger.clone(),
            "SUBPIECE operation completed successfully."
        );
        Ok(())
    }

    // Improved concrete integer subpiece
    fn subpiece_concrete_int(value: u64, bit_offset: u32, output_size_bits: u32) -> ConcreteVar {
        if bit_offset >= 64 {
            // Offset beyond the 64-bit value, return 0
            if output_size_bits <= 64 {
                ConcreteVar::Int(0)
            } else {
                let chunk_count = output_size_bits.div_ceil(64);
                ConcreteVar::LargeInt(vec![0; chunk_count as usize])
            }
        } else {
            let shifted = value >> bit_offset;
            let masked = if output_size_bits >= 64 {
                shifted
            } else {
                shifted & ((1u64 << output_size_bits) - 1)
            };

            if output_size_bits <= 64 {
                ConcreteVar::Int(masked)
            } else {
                // For outputs > 64 bits, create a LargeInt with the value in the first chunk
                let chunk_count = output_size_bits.div_ceil(64);
                let mut result = vec![0; chunk_count as usize];
                result[0] = masked;
                ConcreteVar::LargeInt(result)
            }
        }
    }

    // Improved concrete LargeInt subpiece
    fn subpiece_concrete_largeint(
        values: &[u64],
        bit_offset: u32,
        output_size_bits: u32,
    ) -> ConcreteVar {
        let total_input_bits = (values.len() * 64) as u32;

        if bit_offset >= total_input_bits {
            // Offset beyond input, return 0
            if output_size_bits <= 64 {
                return ConcreteVar::Int(0);
            } else {
                let chunk_count = output_size_bits.div_ceil(64);
                return ConcreteVar::LargeInt(vec![0; chunk_count as usize]);
            }
        }

        // Calculate how many complete 64-bit chunks to skip
        let chunk_offset = (bit_offset / 64) as usize;
        let bit_offset_in_chunk = bit_offset % 64;

        // Calculate output size
        let output_chunk_count = output_size_bits.div_ceil(64);
        let mut result = vec![0u64; output_chunk_count as usize];

        // Extract the required bits
        let mut remaining_bits = output_size_bits;

        for (result_index, i) in (chunk_offset..values.len()).enumerate() {
            if remaining_bits == 0 || result_index >= result.len() {
                break;
            }

            let source_chunk = values[i];
            let shifted_chunk = source_chunk >> bit_offset_in_chunk;

            // If we need bits from the next chunk due to bit offset
            let combined_chunk = if bit_offset_in_chunk > 0 && i + 1 < values.len() {
                let next_chunk = values[i + 1];
                let high_bits = next_chunk << (64 - bit_offset_in_chunk);
                shifted_chunk | high_bits
            } else {
                shifted_chunk
            };

            // Mask if this is the last chunk and we don't need all 64 bits
            if remaining_bits < 64 {
                result[result_index] = combined_chunk & ((1u64 << remaining_bits) - 1);
                remaining_bits = 0;
            } else {
                result[result_index] = combined_chunk;
                remaining_bits -= 64;
            }
        }

        if output_size_bits <= 64 {
            ConcreteVar::Int(result[0])
        } else {
            ConcreteVar::LargeInt(result)
        }
    }

    // Improved BV combination (fix the concatenation order)
    fn combine_largeint(ctx: &'ctx Context, bv_vec: &[BV<'ctx>]) -> BV<'ctx> {
        if bv_vec.is_empty() {
            return BV::from_u64(ctx, 0, 64);
        }

        // bv_vec[0] = low 64 bits, bv_vec[1] = next 64, etc.
        // We need to concatenate in reverse order: high bits first
        let mut result = bv_vec[0].clone();

        for bv in bv_vec.iter().skip(1) {
            // Concatenate: high_bits . low_bits
            result = bv.concat(&result);
        }

        result
    }

    // Improved BV splitting
    fn split_largeint(ctx: &'ctx Context, bv: &BV<'ctx>, total_chunks: usize) -> Vec<BV<'ctx>> {
        let total_bits = bv.get_size();
        let mut result = Vec::with_capacity(total_chunks);

        for chunk_idx in 0..total_chunks {
            let start_bit = chunk_idx * 64;
            let end_bit = std::cmp::min(start_bit + 64, total_bits as usize);

            if start_bit >= total_bits as usize {
                // Beyond the source, add zero chunk
                result.push(BV::from_u64(ctx, 0, 64));
            } else {
                let chunk_size = end_bit - start_bit;
                let extracted = bv.extract((end_bit - 1) as u32, start_bit as u32);

                // Zero-extend to 64 bits if needed
                if chunk_size < 64 {
                    result.push(extracted.zero_ext((64 - chunk_size) as u32));
                } else {
                    result.push(extracted);
                }
            }
        }

        result
    }

    // Extract `out_bits` starting at `bit_offset` from `src_bv`,
    // returning a BV of exactly `out_bits` bits. If offset or size
    // is out of range, it gracefully zeros out everything that is
    // beyond the source BV's length.
    fn subpiece_bv(
        ctx: &'ctx Context,
        src_bv: &BV<'ctx>,
        bit_offset: u32,
        out_bits: u32,
    ) -> BV<'ctx> {
        let src_size = src_bv.get_size();

        // If you asked for 0 bits, just return a 0-bit or 1-bit of zero.
        // (In practice, out_bits=0 may never happen, but let's be safe.)
        if out_bits == 0 {
            // We'll return a 1-bit zero for convenience, or could panic.
            return BV::from_u64(ctx, 0, 1);
        }

        // If the offset is >= src_size, everything is shifted out.
        // So the entire subpiece is just zero.
        if bit_offset >= src_size {
            return BV::from_u64(ctx, 0, out_bits);
        }

        // The maximum bits we can extract from `src_bv` after `bit_offset`
        // is `src_size - bit_offset`.
        let available_bits = src_size - bit_offset;

        // We only need `out_bits`, but if out_bits > available_bits,
        // we'll zero-extend what's left.
        let final_bits = std::cmp::min(out_bits, available_bits);

        // 1) Shift right by `bit_offset`.
        //    This puts the desired subpiece at the bottom of `shifted`.
        let shifted = src_bv.bvlshr(&BV::from_u64(ctx, bit_offset as u64, src_size));

        // 2) Extract the lower `final_bits` bits from `shifted`.
        //    If final_bits == 0, we’d skip and just produce 0,
        //    but we already guaranteed bit_offset < src_size => final_bits > 0
        let extracted = shifted.extract(final_bits - 1, 0);

        // 3) If final_bits < out_bits, we must zero-extend to get the full `out_bits`.
        if final_bits < out_bits {
            extracted.zero_ext(out_bits - final_bits)
        } else {
            extracted
        }
    }

    // Push a new function frame onto the call stack
    // target_func_addr: the address of the function being called (entry point)
    pub fn push_function_frame(&mut self, target_func_addr: u64) {
        // Get current RSP value
        let rsp_value = self
            .state
            .cpu_state
            .lock()
            .unwrap()
            .get_register_by_offset(0x20, 64) // RSP offset = 0x20
            .map(|r| r.concrete.to_u64())
            .unwrap_or(0);

        self.state.call_stack.push(FunctionFrame {
            local_variables: BTreeSet::new(),
            function_addr: target_func_addr,
            rsp_on_entry: rsp_value,
            rsp_on_exit: None,
            is_active: true,
        });
        log!(
            self.state.logger.clone(),
            "[STACK_FRAME] Pushed frame for func 0x{:x}, RSP=0x{:x} (depth: {})",
            target_func_addr,
            rsp_value,
            self.state.call_stack.len()
        );
    }

    // Pop the top function frame from the call stack and clean up variables
    pub fn pop_function_frame(&mut self) {
        // Get current RSP (on return)
        let rsp_on_return = self
            .state
            .cpu_state
            .lock()
            .unwrap()
            .get_register_by_offset(0x20, 64)
            .map(|r| r.concrete.to_u64())
            .unwrap_or(0);

        if let Some(mut finished_frame) = self.state.call_stack.pop() {
            // Remove variables associated with this function's scope from initialized variables
            for var_address in &finished_frame.local_variables {
                self.initialiazed_var.remove(var_address);
                let var_hex = format!("{:x}", var_address);
                self.state.concolic_vars.remove(&var_hex);
                log!(
                    self.state.logger.clone(),
                    "Cleaned up variable at address 0x{:x} ",
                    var_address
                );
            }

            // Mark frame as inactive and record exit RSP
            finished_frame.is_active = false;
            finished_frame.rsp_on_exit = Some(rsp_on_return);

            log!(
                self.state.logger.clone(),
                "[STACK_FRAME] Popped frame for func 0x{:x}, RSP entry=0x{:x}, exit=0x{:x}",
                finished_frame.function_addr,
                finished_frame.rsp_on_entry,
                rsp_on_return
            );

            // Store freed frame for dangling pointer detection
            // Skip Go runtime internal functions to avoid false positives
            // Go runtime functions manage memory differently and stack reuse is expected
            let should_track = !self.is_go_runtime_internal_function(finished_frame.function_addr);

            if should_track {
                // Keep the last 10 freed frames
                self.state.freed_stack_frames.push_back(finished_frame);
                if self.state.freed_stack_frames.len() > 10 {
                    self.state.freed_stack_frames.pop_front();
                }
            } else {
                log!(
                    self.state.logger.clone(),
                    "[STACK_FRAME] Skipping dangling pointer tracking for runtime function 0x{:x}",
                    finished_frame.function_addr
                );
            }
        } else {
            log!(
                self.state.logger.clone(),
                "Call stack is empty. No frame to pop."
            );
        }
    }

    // Check if the current instruction is a function return
    fn is_function_return(&self, instruction: &Inst) -> bool {
        instruction.opcode == Opcode::Return
    }

    fn cleanup_finished_function_variables(&mut self, instruction: &Inst) {
        // Check if the current instruction is a function return
        if self.is_function_return(instruction) {
            // Pop the function frame and clean up variables
            self.pop_function_frame();
        }
    }

    /// Check if a memory access is to a freed stack frame (dangling pointer)
    /// Returns (is_dangling, function_addr, frame_rsp) if dangling
    pub fn check_dangling_pointer_access(&self, address: u64) -> Option<(u64, u64)> {
        // Get current RSP
        let current_rsp = self
            .state
            .cpu_state
            .lock()
            .unwrap()
            .get_register_by_offset(0x20, 64)
            .map(|r| r.concrete.to_u64())
            .unwrap_or(0);

        // Check if address points to any freed stack frame
        for freed_frame in &self.state.freed_stack_frames {
            let frame_start = freed_frame.rsp_on_entry;
            let frame_end = freed_frame.rsp_on_exit.unwrap_or(freed_frame.rsp_on_entry);

            // Normalize (stack grows down, so frame_start > frame_end)
            let (low, high) = if frame_start > frame_end {
                (frame_end, frame_start)
            } else {
                (frame_start, frame_end)
            };

            // Check if address is in the freed frame range
            // AND current RSP is above the freed frame (meaning it's truly freed)
            if address >= low && address < high && current_rsp >= high {
                log!(
                    self.state.logger.clone(),
                    "[DANGLING_POINTER] Access to freed frame! addr=0x{:x}, func=0x{:x}, frame_rsp=[0x{:x}..0x{:x}], current_rsp=0x{:x}",
                    address, freed_frame.function_addr, low, high, current_rsp
                );
                return Some((freed_frame.function_addr, frame_start));
            }
        }
        None
    }

    /// Check if a function address corresponds to a Go runtime internal function
    /// These functions (runtime.*, internal/abi.*, etc.) manage memory differently
    /// and stack reuse after their return is expected, not a vulnerability
    /// Goal : avoid false positives (during dangling pointers detection)
    fn is_go_runtime_internal_function(&self, func_addr: u64) -> bool {
        // Check the source language - only filter for Go binaries
        let source_lang = std::env::var("SOURCE_LANG").unwrap_or_default();
        if source_lang.to_lowercase() != "go" {
            return false;
        }

        // Look up function name from the existing symbol_table (key is hex address string)
        let func_addr_hex = format!("{:x}", func_addr);
        if let Some(func_name) = self.symbol_table.get(&func_addr_hex) {
            // Filter out Go runtime and standard library internal functions that commonly cause false positives
            // These prefixes indicate runtime/stdlib functions where stack reuse is normal
            let runtime_prefixes = [
                // Go runtime
                "runtime.",
                "internal/abi.",
                "internal/runtime",
                // Sync primitives
                "sync.",
                "sync/atomic.",
                "internal/sync.",
                // Reflection
                "reflect.",
                // Common stdlib packages that manage memory/goroutines internally
                "time.",
                "context.",
                "os.",
                "io.",
                "fmt.",
                "strings.",
                "bytes.",
                "encoding/",
                "math.",
                "strconv.",
                "unicode.",
                "sort.",
                "container/",
            ];

            for prefix in &runtime_prefixes {
                if func_name.starts_with(prefix) {
                    return true;
                }
            }
        }

        false
    }
}

impl<'ctx> fmt::Display for ConcolicExecutor<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "***")?;
        writeln!(f, "ConcolicExecutor State after the instruction:")?;
        writeln!(f, "Current Address: {:x}", self.current_address.unwrap())?;
        writeln!(f, "Instruction Counter: {}", self.instruction_counter)?;
        writeln!(f, "Unique Variables:")?;
        for (key, value) in &self.unique_variables {
            writeln!(f, "  {}: {}", key, value)?;
        }
        Ok(())
    }
}
