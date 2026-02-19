// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/// Overlay mechanism for concolic exploration of untaken paths
/// This provides copy-on-write semantics for CPU state and memory
/// to enable lightweight exploration without full state cloning
use super::cpu_state::{CpuConcolicValue, CpuState};
use super::memory_x86_64::MemoryRegion;
use crate::concolic::ConcolicVar;
use std::collections::BTreeMap;
use std::sync::Arc;
use z3::ast::BV;
use z3::Context;

/// Overlay for a single memory region
/// Uses copy-on-write: concrete data is cloned on first write,
/// symbolic data starts empty and falls back to base if not present
#[derive(Debug)]
pub struct MemoryRegionOverlay<'ctx> {
    /// Base region (read-only reference)
    base_region: *const MemoryRegion<'ctx>,
    /// Concrete data overlay (None until first write)
    concrete_overlay: Option<Vec<u8>>,
    /// Symbolic data overlay (only modified entries)
    symbolic_overlay: BTreeMap<usize, Arc<BV<'ctx>>>,
}

impl<'ctx> MemoryRegionOverlay<'ctx> {
    /// Create a new overlay for a memory region
    pub fn new(base_region: &MemoryRegion<'ctx>) -> Self {
        Self {
            base_region: base_region as *const MemoryRegion<'ctx>,
            concrete_overlay: None,
            symbolic_overlay: BTreeMap::new(),
        }
    }

    /// Get base region (unsafe but necessary for accessing read-only data)
    #[inline]
    fn base(&self) -> &MemoryRegion<'ctx> {
        unsafe { &*self.base_region }
    }

    /// Get the size of this memory region
    pub fn size(&self) -> usize {
        self.base().concrete_data.len()
    }

    /// Read concrete byte at offset
    pub fn read_concrete_byte(&self, offset: usize) -> Option<u8> {
        if let Some(ref overlay_data) = self.concrete_overlay {
            overlay_data.get(offset).copied()
        } else {
            self.base().concrete_data.get(offset).copied()
        }
    }

    /// Read concrete bytes at offset
    pub fn read_concrete_bytes(&self, offset: usize, size: usize) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(size);
        for i in 0..size {
            result.push(self.read_concrete_byte(offset + i)?);
        }
        Some(result)
    }

    /// Read symbolic value at offset (checks overlay first, then base)
    pub fn read_symbolic(&self, offset: usize) -> Option<Arc<BV<'ctx>>> {
        if let Some(bv) = self.symbolic_overlay.get(&offset) {
            Some(Arc::clone(bv))
        } else {
            self.base().symbolic_data.get(&offset).map(Arc::clone)
        }
    }

    /// Write concrete byte at offset (clones concrete data on first write)
    pub fn write_concrete_byte(&mut self, offset: usize, value: u8) -> Result<(), String> {
        // Ensure concrete overlay exists
        if self.concrete_overlay.is_none() {
            // First write: clone the base concrete data
            self.concrete_overlay = Some(self.base().concrete_data.clone());
        }

        // Write to the overlay
        if let Some(ref mut overlay_data) = self.concrete_overlay {
            if offset < overlay_data.len() {
                overlay_data[offset] = value;
                Ok(())
            } else {
                Err(format!(
                    "Offset {} out of bounds for concrete overlay (size {})",
                    offset,
                    overlay_data.len()
                ))
            }
        } else {
            unreachable!("Concrete overlay should exist after initialization");
        }
    }

    /// Write concrete bytes at offset
    pub fn write_concrete_bytes(&mut self, offset: usize, data: &[u8]) -> Result<(), String> {
        for (i, &byte) in data.iter().enumerate() {
            self.write_concrete_byte(offset + i, byte)?;
        }
        Ok(())
    }

    /// Write symbolic value at offset (only modifies overlay)
    pub fn write_symbolic(&mut self, offset: usize, value: Arc<BV<'ctx>>) {
        self.symbolic_overlay.insert(offset, value);
    }

    /// Check if a given address range is within this region
    pub fn contains(&self, address: u64, size: usize) -> bool {
        self.base().contains(address, size)
    }

    /// Get start address of the region
    pub fn start_address(&self) -> u64 {
        self.base().start_address
    }

    /// Get end address of the region
    pub fn end_address(&self) -> u64 {
        self.base().end_address
    }

    /// Get protection flags
    pub fn prot(&self) -> i32 {
        self.base().prot
    }
}

/// Overlay for CPU registers
/// Uses copy-on-write: only modified registers are stored
#[derive(Debug)]
pub struct CpuStateOverlay<'ctx> {
    /// Base CPU state (read-only reference)
    base_state: *const CpuState<'ctx>,
    /// Overlay for modified registers (offset -> value)
    pub(crate) register_overlay: BTreeMap<u64, CpuConcolicValue<'ctx>>,
    /// Context for Z3
    ctx: &'ctx Context,
}

impl<'ctx> CpuStateOverlay<'ctx> {
    /// Create a new overlay for CPU state
    pub fn new(base_state: &CpuState<'ctx>, ctx: &'ctx Context) -> Self {
        Self {
            base_state: base_state as *const CpuState<'ctx>,
            register_overlay: BTreeMap::new(),
            ctx,
        }
    }

    /// Get base CPU state (unsafe but necessary for accessing read-only data)
    #[inline]
    pub(crate) fn base(&self) -> &CpuState<'ctx> {
        unsafe { &*self.base_state }
    }

    /// Get register value by offset (checks overlay first, then base)
    pub fn get_register_by_offset(
        &self,
        offset: u64,
        access_size: u32,
    ) -> Option<CpuConcolicValue<'ctx>> {
        // First check if there's an overlay for this register
        if let Some(overlayed_value) = self.register_overlay.get(&offset) {
            // If the access size matches, return directly
            if overlayed_value.get_size() == access_size {
                return Some(overlayed_value.clone());
            }
            // Otherwise, we might need to extract a portion
            // For simplicity, if sizes don't match exactly, fall through to base logic
        }

        // Check base state
        self.base().get_register_by_offset(offset, access_size)
    }

    /// Set register value by offset (writes to overlay only)
    pub fn set_register_value_by_offset(
        &mut self,
        offset: u64,
        new_value: ConcolicVar<'ctx>,
        _new_size: u32,
    ) -> Result<(), String> {
        // For overlay, we simplify by directly storing the value
        // (In a full implementation, you might want to handle sub-register writes more carefully)

        // Create a CpuConcolicValue from the ConcolicVar
        let cpu_value = CpuConcolicValue {
            concrete: new_value.concrete.clone(),
            symbolic: new_value.symbolic.clone(),
            ctx: self.ctx,
        };

        self.register_overlay.insert(offset, cpu_value);
        Ok(())
    }

    /// Get all register offsets and names from the register map
    pub fn get_register_map(&self) -> &BTreeMap<u64, (String, u32)> {
        &self.base().register_map
    }

    /// Resolve register offset from name
    pub fn resolve_offset_from_register_name(&self, reg_name: &str) -> Option<u64> {
        self.base().resolve_offset_from_register_name(reg_name)
    }

    /// Get a reference to all registers (for iteration, returns base merged with overlay)
    pub fn iter_registers(&self) -> impl Iterator<Item = (u64, CpuConcolicValue<'ctx>)> + '_ {
        // This is a simplified version - in reality you'd want to merge base and overlay properly
        // For now, just iterate over the overlay
        self.register_overlay
            .iter()
            .map(|(&offset, value)| (offset, value.clone()))
    }
}

/// Complete overlay state for exploring untaken paths
#[derive(Debug)]
pub struct OverlayState<'ctx> {
    /// CPU state overlay
    pub cpu_overlay: CpuStateOverlay<'ctx>,
    /// Memory region overlays (address -> overlay)
    pub memory_overlays: BTreeMap<u64, MemoryRegionOverlay<'ctx>>,
    /// Standalone memory writes (address -> byte) for syscall handlers
    /// These are not tied to memory regions and are discarded when overlay ends
    pub standalone_memory_writes: BTreeMap<u64, u8>,
    /// Depth of exploration in this overlay
    pub exploration_depth: usize,
    /// Starting address of this overlay exploration
    pub start_address: u64,
}

impl<'ctx> OverlayState<'ctx> {
    /// Create a new overlay state for exploring from a given address
    /// The CPU overlay is initialized with RIP set to the start address
    pub fn new(
        base_cpu_state: &CpuState<'ctx>,
        rip_offset: u64,
        start_address: u64,
        ctx: &'ctx Context,
    ) -> Result<Self, String> {
        let mut cpu_overlay = CpuStateOverlay::new(base_cpu_state, ctx);

        // Set RIP to the start address in the overlay
        let rip_value = ConcolicVar::new_concrete_and_symbolic_int(
            start_address,
            BV::from_u64(ctx, start_address, 64),
            ctx,
        );
        cpu_overlay.set_register_value_by_offset(rip_offset, rip_value, 64)?;

        Ok(Self {
            cpu_overlay,
            memory_overlays: BTreeMap::new(),
            standalone_memory_writes: BTreeMap::new(),
            exploration_depth: 0,
            start_address,
        })
    }

    /// Get or create a memory overlay for a given region
    pub fn get_or_create_memory_overlay(
        &mut self,
        region: &MemoryRegion<'ctx>,
    ) -> &mut MemoryRegionOverlay<'ctx> {
        let start_addr = region.start_address;
        self.memory_overlays
            .entry(start_addr)
            .or_insert_with(|| MemoryRegionOverlay::new(region))
    }

    /// Read from memory (checks overlay first, then base)
    /// Returns per-byte symbolic data: one `Option<Arc<BV>>` per byte, each BV being 8 bits.
    /// This mirrors how `MemoryX86_64::read_memory` returns symbolic data and avoids the
    /// byte-fill bug where only the symbolic at the base offset (byte 0) was returned and
    /// then replicated across every byte position, producing patterns like #x0808080808080808.
    pub fn read_memory(
        &mut self,
        address: u64,
        size: usize,
        base_region: &MemoryRegion<'ctx>,
    ) -> Option<(Vec<u8>, Vec<Option<Arc<BV<'ctx>>>>)> {
        if !base_region.contains(address, size) {
            return None;
        }

        let overlay = self.get_or_create_memory_overlay(base_region);
        let offset = (address - overlay.start_address()) as usize;

        let concrete_data = overlay.read_concrete_bytes(offset, size)?;

        // Read symbolic data per-byte, just like MemoryX86_64::read_memory does.
        // This correctly handles both:
        //   (a) addresses written by the overlay (per-byte 8-bit BVs stored at offset+i), and
        //   (b) addresses inherited from the base region (also per-byte 8-bit BVs at offset+i).
        let symbolic_per_byte: Vec<Option<Arc<BV<'ctx>>>> = (0..size)
            .map(|i| overlay.read_symbolic(offset + i))
            .collect();

        Some((concrete_data, symbolic_per_byte))
    }

    /// Write to memory (writes to overlay only)
    /// Symbolic data is stored **per-byte** (8-bit BVs at offset+i), mirroring the storage
    /// convention of `MemoryX86_64::write_value`.  Previously the full word BV was stored only
    /// at the base offset, so reads of non-zero byte positions fell back to the base region's
    /// per-byte storage and returned a stale 8-bit BV that was then replicated across all byte
    /// positions, producing the #x0808080808080808 fill-pattern bug.
    pub fn write_memory(
        &mut self,
        address: u64,
        concrete_data: &[u8],
        symbolic_data: Option<Arc<BV<'ctx>>>,
        base_region: &MemoryRegion<'ctx>,
    ) -> Result<(), String> {
        if !base_region.contains(address, concrete_data.len()) {
            return Err(format!(
                "Address 0x{:x} with size {} is not contained in region 0x{:x}-0x{:x}",
                address,
                concrete_data.len(),
                base_region.start_address,
                base_region.end_address
            ));
        }

        let overlay = self.get_or_create_memory_overlay(base_region);
        let offset = (address - overlay.start_address()) as usize;

        // Write concrete data
        overlay.write_concrete_bytes(offset, concrete_data)?;

        // Write symbolic data per-byte by extracting 8-bit slices from the word BV.
        // This is consistent with MemoryX86_64::write_value and ensures that subsequent
        // per-byte reads (read_symbolic(offset + i)) return the correct 8-bit slice rather
        // than None (which would fall back to a stale base-region byte).
        if let Some(sym_data) = symbolic_data {
            let byte_count = concrete_data.len();
            let bv_size = sym_data.get_size();
            for i in 0..byte_count {
                let low = (i * 8) as u32;
                let high = low + 7;
                // Clamp high to the actual BV width in case of narrow symbolics
                let byte_bv = if high < bv_size {
                    sym_data.extract(high, low)
                } else if low < bv_size {
                    sym_data.extract(bv_size - 1, low)
                } else {
                    // Byte is beyond the symbolic width; no symbolic to record
                    continue;
                };
                overlay.write_symbolic(offset + i, Arc::new(byte_bv));
            }
        }

        Ok(())
    }

    /// Write raw bytes to overlay memory storage (for syscall handlers)
    /// This uses a simple standalone storage indexed by address, not tied to memory regions
    /// These writes will be visible to overlay reads but are discarded when overlay ends
    pub fn write_memory_bytes(&mut self, address: u64, data: &[u8]) {
        // Store in a simple address-indexed map within the existing memory_overlays structure
        // We use a synthetic region at the address itself for simplicity
        // Since this is overlay-only and will be discarded, we don't need complex region matching
        for (i, byte) in data.iter().enumerate() {
            let addr = address + i as u64;
            // Store each byte - the overlay read logic will find these
            // We use region_start = address for the standalone storage
            self.standalone_memory_writes.insert(addr, *byte);
        }
    }

    /// Read from standalone memory writes (for overlay reads)
    pub fn read_standalone_memory(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(size);
        for i in 0..size {
            let addr = address + i as u64;
            if let Some(byte) = self.standalone_memory_writes.get(&addr) {
                result.push(*byte);
            } else {
                return None; // Not all bytes present in overlay
            }
        }
        Some(result)
    }

    /// Increment exploration depth
    pub fn increment_depth(&mut self) {
        self.exploration_depth += 1;
    }

    /// Get current exploration depth
    pub fn get_depth(&self) -> usize {
        self.exploration_depth
    }

    /// Get list of modified registers in overlay
    pub fn get_modified_registers(&self) -> Vec<(u64, String)> {
        let base_cpu = self.cpu_overlay.base();

        self.cpu_overlay
            .register_overlay
            .iter()
            .map(|(offset, concolic_val)| {
                // Get register name from the base CPU state's register_map
                let reg_name = base_cpu
                    .register_map
                    .get(offset)
                    .map(|(name, _size)| name.as_str())
                    .unwrap_or("UNKNOWN");

                let value_str = format!("{} = 0x{:x}", reg_name, concolic_val.concrete.to_u64());
                (*offset, value_str)
            })
            .collect()
    }

    /// Get list of modified memory regions and their modified address ranges
    pub fn get_modified_memory_regions(&self) -> Vec<(u64, u64, Vec<u64>)> {
        let mut result = Vec::new();

        for (region_start, overlay) in &self.memory_overlays {
            let mut modified_addrs = Vec::new();

            // Collect addresses from symbolic overlay (these were definitely written)
            for offset in overlay.symbolic_overlay.keys() {
                modified_addrs.push(*region_start + (*offset as u64));
            }

            // If concrete overlay exists, it means at least one write occurred
            if overlay.concrete_overlay.is_some() {
                // We don't track exact offsets, but we know the region was modified
                let region_end = *region_start + overlay.size() as u64;
                result.push((*region_start, region_end, modified_addrs));
            } else if !modified_addrs.is_empty() {
                // Only symbolic writes, no concrete writes
                let region_end = *region_start + overlay.size() as u64;
                result.push((*region_start, region_end, modified_addrs));
            }
        }

        result
    }

    /// Get count of modified registers
    pub fn get_modified_register_count(&self) -> usize {
        self.cpu_overlay.register_overlay.len()
    }

    /// Get count of modified memory regions
    pub fn get_modified_memory_region_count(&self) -> usize {
        self.memory_overlays.len()
    }
}
