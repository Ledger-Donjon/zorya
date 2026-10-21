// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Go toolchain identification and standard-library advisories.
//!
//! A Go binary records the toolchain that built it in its `.go.buildinfo`
//! section. Zorya reads it so a report states which standard library was
//! analysed, and checks it against a table of concurrency advisories whose
//! bug lives in the standard library itself (e.g. CVE-2020-15586 in
//! `net/http`): when the binary was built with a toolchain that already
//! contains the fix, no amount of exploration can reproduce the race and the
//! run says so instead of reporting "no race".

use serde_json::{json, Value};

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

/// `go1.26.5` → `(1, 26, 5)`, `go1.22` → `(1, 22, 0)`, `go1.23rc1` →
/// `(1, 23, 0)`. Experiment suffixes (`go1.24 X:boringcrypto`) are ignored.
pub fn parse_go_version(v: &str) -> Option<(u32, u32, u32)> {
    let v = v.strip_prefix("go")?;
    let v = v.split([' ', '-', '+']).next()?;
    let mut nums = v.split('.').map(|part| {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u32>().ok()
    });
    let major = nums.next()??;
    let minor = nums.next().flatten().unwrap_or(0);
    let patch = nums.next().flatten().unwrap_or(0);
    Some((major, minor, patch))
}

/// A concurrency bug located in the Go standard library.
#[derive(Debug)]
pub struct StdlibAdvisory {
    pub id: &'static str,
    pub package: &'static str,
    pub summary: &'static str,
    /// First fixed release of each patched branch.
    pub fixed: &'static [(u32, u32, u32)],
    /// Functions whose presence shows the binary links the vulnerable code.
    pub symbols: &'static [&'static str],
}

/// Standard-library concurrency advisories Zorya knows about.
pub const STDLIB_ADVISORIES: &[StdlibAdvisory] = &[StdlibAdvisory {
    id: "CVE-2020-15586",
    package: "net/http",
    summary: "data race between a Handler reading an Expect: 100-continue request body \
              and the server's implicit 100 Continue response write",
    fixed: &[(1, 13, 13), (1, 14, 5)],
    symbols: &[
        "net/http.(*expectContinueReader).Read",
        "net/http.(*conn).serve",
    ],
}];

/// Whether toolchain `v` already contains a fix released on the branches
/// listed in `fixed`: the same branch at or past the fixing patch, or any
/// newer branch.
pub fn toolchain_contains_fix(v: (u32, u32, u32), fixed: &[(u32, u32, u32)]) -> bool {
    if let Some(&(_, _, patch)) = fixed.iter().find(|f| f.0 == v.0 && f.1 == v.1) {
        return v.2 >= patch;
    }
    fixed
        .iter()
        .map(|f| (f.0, f.1))
        .max()
        .is_some_and(|newest| (v.0, v.1) > newest)
}

/// Outcome of checking one advisory against an analysed binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryStatus {
    pub id: &'static str,
    pub package: &'static str,
    /// `fixed_in_toolchain`, `vulnerable_toolchain` or `vendored_copy`.
    pub status: &'static str,
    pub message: String,
}

impl AdvisoryStatus {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "package": self.package,
            "status": self.status,
            "message": self.message,
        })
    }
}

/// Check every advisory whose vulnerable package the binary links.
///
/// `has_function` tells whether a function symbol is present; `has_copy`
/// whether a vendored / modelled copy of a package is linked (a non-stdlib
/// package path ending in that package). Packages listed in the
/// comma-separated `ZORYA_VENDORED_STDLIB` are treated as provided by such a
/// copy as well.
pub fn check_advisories(
    version: &str,
    has_function: impl Fn(&str) -> bool,
    has_copy: impl Fn(&str) -> bool,
) -> Vec<AdvisoryStatus> {
    let vendored_env = std::env::var("ZORYA_VENDORED_STDLIB").unwrap_or_default();
    let declared: Vec<&str> = vendored_env
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let Some(v) = parse_go_version(version) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for adv in STDLIB_ADVISORIES {
        let vendored = declared.contains(&adv.package) || has_copy(adv.package);
        let linked = adv.symbols.iter().any(|s| has_function(s));
        if !linked && !vendored {
            continue;
        }
        let fixed_list = adv
            .fixed
            .iter()
            .map(|(a, b, c)| format!("go{a}.{b}.{c}"))
            .collect::<Vec<_>>()
            .join(", ");
        let (status, message) = if vendored {
            (
                "vendored_copy",
                format!(
                    "{} ({}): the binary links a vendored / modelled copy of {}; the \
                     toolchain version ({version}) does not decide whether the bug is present",
                    adv.id, adv.summary, adv.package
                ),
            )
        } else if toolchain_contains_fix(v, adv.fixed) {
            (
                "fixed_in_toolchain",
                format!(
                    "{} ({}): built with {version}, which already contains the fix (fixed in \
                     {fixed_list}); the race cannot occur in this binary. Rebuild with a \
                     vulnerable toolchain or link a vendored copy of the vulnerable {} \
                     (see ZORYA_VENDORED_STDLIB)",
                    adv.id, adv.summary, adv.package
                ),
            )
        } else {
            (
                "vulnerable_toolchain",
                format!(
                    "{} ({}): built with {version}, older than the fix (fixed in {fixed_list}); \
                     the vulnerable {} code is linked",
                    adv.id, adv.summary, adv.package
                ),
            )
        };
        out.push(AdvisoryStatus {
            id: adv.id,
            package: adv.package,
            status,
            message,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toolchain_versions() {
        assert_eq!(parse_go_version("go1.26.5"), Some((1, 26, 5)));
        assert_eq!(parse_go_version("go1.22"), Some((1, 22, 0)));
        assert_eq!(parse_go_version("go1.23rc1"), Some((1, 23, 0)));
        assert_eq!(
            parse_go_version("go1.24.1 X:boringcrypto"),
            Some((1, 24, 1))
        );
        assert_eq!(parse_go_version("devel"), None);
    }

    #[test]
    fn fix_detection_per_branch() {
        let fixed = &[(1, 13, 13), (1, 14, 5)];
        assert!(!toolchain_contains_fix((1, 14, 4), fixed));
        assert!(toolchain_contains_fix((1, 14, 5), fixed));
        assert!(!toolchain_contains_fix((1, 13, 12), fixed));
        assert!(toolchain_contains_fix((1, 13, 13), fixed));
        assert!(!toolchain_contains_fix((1, 12, 17), fixed));
        assert!(toolchain_contains_fix((1, 26, 5), fixed));
    }

    #[test]
    fn advisory_statuses() {
        let links_http = |s: &str| s == "net/http.(*conn).serve";
        let none = |_: &str| false;
        let fixed = check_advisories("go1.26.5", links_http, none);
        assert_eq!(fixed.len(), 1);
        assert_eq!(fixed[0].status, "fixed_in_toolchain");
        assert!(fixed[0].message.contains("go1.14.5"));
        let vuln = check_advisories("go1.14.4", links_http, none);
        assert_eq!(vuln[0].status, "vulnerable_toolchain");
        let vendored = check_advisories("go1.26.5", none, |p| p == "net/http");
        assert_eq!(vendored[0].status, "vendored_copy");
        assert!(check_advisories("go1.26.5", none, none).is_empty());
    }

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
