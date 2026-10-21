// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Go toolchain identification.
//!
//! A Go binary records the toolchain that built it in its `.go.buildinfo`
//! section. Zorya reads it so a report states which standard library was
//! analysed.

/// What the build-info blob says about a Go binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoBuildInfo {
    /// Toolchain version string, e.g. `go1.26.5`.
    pub version: String,
    /// Main module path from the module info (`path` line), if present.
    pub main_path: Option<String>,
    /// `build` settings (`-gcflags`, `GOARCH`, ...).
    pub settings: Vec<(String, String)>,
}

const BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// Parse the Go build-info blob of `elf_data`. Returns `None` for non-Go
/// binaries or unreadable blobs.
pub fn read_buildinfo(elf_data: &[u8]) -> Option<GoBuildInfo> {
    let elf = goblin::elf::Elf::parse(elf_data).ok()?;
    let section_off = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".go.buildinfo"))
        .map(|s| s.sh_offset as usize);
    let off = section_off
        .filter(|&o| elf_data.get(o..o + BUILDINFO_MAGIC.len()) == Some(BUILDINFO_MAGIC))
        .or_else(|| find_subslice(elf_data, BUILDINFO_MAGIC))?;
    let blob = elf_data.get(off..)?;
    if blob.len() < 32 {
        return None;
    }
    let ptr_size = blob[14] as usize;
    let flags = blob[15];
    let (version, modinfo) = if flags & 0x2 != 0 {
        // Go 1.18+: both strings are inlined after the 32-byte header as
        // uvarint-length-prefixed bytes.
        let (version, rest) = read_varint_string(&blob[32..])?;
        let (modinfo, _) = read_varint_string(rest).unwrap_or_default();
        (version, modinfo)
    } else {
        // Go < 1.18: the header holds pointers to Go string headers.
        let big_endian = flags & 0x1 != 0;
        let read_ptr = |b: &[u8]| -> Option<u64> {
            let b = b.get(..ptr_size)?;
            Some(match (ptr_size, big_endian) {
                (8, false) => u64::from_le_bytes(b.try_into().ok()?),
                (8, true) => u64::from_be_bytes(b.try_into().ok()?),
                (4, false) => u32::from_le_bytes(b.try_into().ok()?) as u64,
                (4, true) => u32::from_be_bytes(b.try_into().ok()?) as u64,
                _ => return None,
            })
        };
        let read_go_string = |vaddr: u64| -> Option<String> {
            let hdr = vaddr_slice(&elf, elf_data, vaddr, 2 * ptr_size)?;
            let data = read_ptr(hdr)?;
            let len = read_ptr(&hdr[ptr_size..])? as usize;
            let bytes = vaddr_slice(&elf, elf_data, data, len)?;
            Some(String::from_utf8_lossy(bytes).into_owned())
        };
        let version = read_go_string(read_ptr(&blob[16..])?)?;
        let modinfo = read_ptr(&blob[16 + ptr_size..])
            .and_then(read_go_string)
            .unwrap_or_default();
        (version, modinfo)
    };
    if !version.starts_with("go") {
        return None;
    }
    // Module info is framed by 16-byte sentinels.
    let modinfo = if modinfo.len() >= 33 {
        modinfo
            .get(16..modinfo.len() - 16)
            .unwrap_or("")
            .to_string()
    } else {
        modinfo
    };
    let mut main_path = None;
    let mut settings = Vec::new();
    for line in modinfo.lines() {
        let mut parts = line.splitn(2, '\t');
        match (parts.next(), parts.next()) {
            (Some("path"), Some(p)) => main_path = Some(p.to_string()),
            (Some("build"), Some(kv)) => {
                if let Some((k, v)) = kv.split_once('=') {
                    settings.push((k.to_string(), v.to_string()));
                }
            }
            _ => {}
        }
    }
    Some(GoBuildInfo {
        version,
        main_path,
        settings,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn read_varint_string(b: &[u8]) -> Option<(String, &[u8])> {
    let mut len: u64 = 0;
    let mut shift = 0;
    let mut i = 0;
    loop {
        let byte = *b.get(i)?;
        len |= ((byte & 0x7f) as u64) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    let end = i.checked_add(len as usize)?;
    let s = b.get(i..end)?;
    Some((String::from_utf8_lossy(s).into_owned(), &b[end..]))
}

fn vaddr_slice<'a>(
    elf: &goblin::elf::Elf<'_>,
    data: &'a [u8],
    vaddr: u64,
    len: usize,
) -> Option<&'a [u8]> {
    let ph = elf.program_headers.iter().find(|ph| {
        ph.p_type == goblin::elf::program_header::PT_LOAD
            && vaddr >= ph.p_vaddr
            && vaddr + len as u64 <= ph.p_vaddr + ph.p_filesz
    })?;
    let off = (ph.p_offset + (vaddr - ph.p_vaddr)) as usize;
    data.get(off..off + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_buildinfo_strings() {
        let mut blob = vec![0u8; 32];
        blob[..14].copy_from_slice(BUILDINFO_MAGIC);
        blob[14] = 8;
        blob[15] = 2;
        blob.push(8);
        blob.extend_from_slice(b"go1.26.5");
        let (v, rest) = read_varint_string(&blob[32..]).unwrap();
        assert_eq!(v, "go1.26.5");
        assert!(rest.is_empty());
    }
}
