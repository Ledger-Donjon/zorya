// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Address-to-symbol index of the analysed binary.
//!
//! Built once from the ELF symbol table by
//! [`crate::executor::ConcolicExecutor::populate_symbol_table`] and installed
//! process-wide, so plugins and report writers can name the function that
//! issued an access without holding a reference to the executor. It also
//! classifies Go functions (application code, runtime internals, the map
//! implementation) and maps report PCs to source lines through
//! `go tool addr2line` (or binutils `addr2line` for non-Go binaries).

use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use goblin::elf::sym::{STT_FUNC, STT_OBJECT};
use goblin::elf::Elf;

/// Sorted function ranges and pointer-sized globals of one binary.
#[derive(Debug, Default)]
pub struct FuncIndex {
    /// `(start, end, name)`, sorted by `start`. Zero-sized symbols get the
    /// distance to the next function as their size.
    funcs: Vec<(u64, u64, String)>,
    /// `(address, name)` of 8-byte data objects, the shape of a package-level
    /// map variable (`var m = map[K]V{}` holds a single `*Map`).
    pointer_globals: Vec<(u64, String)>,
}

static INDEX: OnceLock<FuncIndex> = OnceLock::new();

impl FuncIndex {
    /// Index the static symbol table of `elf_data`. Returns an empty index
    /// when the ELF cannot be parsed.
    pub fn from_elf(elf_data: &[u8]) -> Self {
        let Ok(elf) = Elf::parse(elf_data) else {
            return Self::default();
        };
        let mut funcs: Vec<(u64, u64, String)> = Vec::new();
        let mut pointer_globals = Vec::new();
        for sym in elf.syms.iter() {
            let Some(name) = elf.strtab.get_at(sym.st_name) else {
                continue;
            };
            if name.is_empty() || sym.st_value == 0 {
                continue;
            }
            match goblin::elf::sym::st_type(sym.st_info) {
                STT_FUNC => {
                    funcs.push((sym.st_value, sym.st_value + sym.st_size, name.to_string()))
                }
                STT_OBJECT if sym.st_size == 8 => {
                    pointer_globals.push((sym.st_value, name.to_string()))
                }
                _ => {}
            }
        }
        Self::from_parts(funcs, pointer_globals)
    }

    /// Build an index from explicit function ranges (`(start, end, name)`)
    /// and pointer-sized globals. Used by [`Self::from_elf`] and by tests.
    pub fn from_parts(
        mut funcs: Vec<(u64, u64, String)>,
        pointer_globals: Vec<(u64, String)>,
    ) -> Self {
        funcs.sort_by_key(|f| f.0);
        funcs.dedup_by_key(|f| f.0);
        for i in 0..funcs.len() {
            if funcs[i].1 <= funcs[i].0 {
                funcs[i].1 = funcs.get(i + 1).map_or(funcs[i].0 + 1, |next| next.0);
            }
        }
        Self {
            funcs,
            pointer_globals,
        }
    }

    /// The function containing `pc`, as `(start, end, name)`.
    pub fn function_at(&self, pc: u64) -> Option<(u64, u64, &str)> {
        let idx = self.funcs.partition_point(|f| f.0 <= pc).checked_sub(1)?;
        let (start, end, name) = &self.funcs[idx];
        (pc < *end).then_some((*start, *end, name.as_str()))
    }

    /// Pointer-sized data symbols, candidates for naming a map header.
    pub fn pointer_globals(&self) -> &[(u64, String)] {
        &self.pointer_globals
    }

    /// Number of indexed functions.
    pub fn function_count(&self) -> usize {
        self.funcs.len()
    }

    /// Whether a function named exactly `name` exists.
    pub fn has_function(&self, name: &str) -> bool {
        self.funcs.iter().any(|(_, _, n)| n == name)
    }
}

/// Install the process-wide index. Later calls are ignored (one binary per
/// run).
pub fn install(index: FuncIndex) {
    let _ = INDEX.set(index);
}

/// The process-wide index, once installed.
pub fn get() -> Option<&'static FuncIndex> {
    INDEX.get()
}

/// Name of the function containing `pc` in the installed index.
pub fn function_name_at(pc: u64) -> Option<&'static str> {
    get()?.function_at(pc).map(|(_, _, name)| name)
}

/// Go package path of a symbol: `main.rewriteCSS` → `main`,
/// `github.com/a/b.(*T).M` → `github.com/a/b`,
/// `internal/runtime/maps.(*Map).getWithKey` → `internal/runtime/maps`.
pub fn go_package(name: &str) -> &str {
    let after_slash = name.rfind('/').map_or(0, |i| i + 1);
    match name[after_slash..].find('.') {
        Some(dot) => &name[..after_slash + dot],
        None => name,
    }
}

/// A package path outside the standard library: its first element contains
/// a dot (`github.com/...`, `example.test/...`).
fn is_third_party_package(pkg: &str) -> bool {
    pkg.split('/')
        .next()
        .is_some_and(|first| first.contains('.'))
}

/// Code written by the program author: package `main` or a module outside
/// the standard library.
pub fn is_application_function(name: &str) -> bool {
    let pkg = go_package(name);
    pkg == "main" || is_third_party_package(pkg)
}

/// Go runtime and runtime-adjacent code whose memory traffic is engine
/// plumbing rather than program behaviour: `runtime`, `internal/...`,
/// `sync`, `sync/atomic`, compiler-generated type and `go:` helpers.
pub fn is_runtime_internal_function(name: &str) -> bool {
    let pkg = go_package(name);
    pkg == "runtime"
        || pkg.starts_with("runtime/")
        || pkg.starts_with("internal/")
        || pkg == "sync"
        || pkg == "sync/atomic"
        || name.starts_with("type:")
        || name.starts_with("go:")
        || name.starts_with("aeshash")
        || name == "gogo"
}

/// The Go map implementation and the hash functions it calls. Accesses
/// issued from here are represented by the [`crate::plugins::Event::MapAccess`]
/// of the application call site instead.
pub fn is_map_internal_function(name: &str) -> bool {
    let name = name.strip_suffix(".abi0").unwrap_or(name);
    const PREFIXES: &[&str] = &[
        "internal/runtime/maps.",
        "runtime.map",
        "runtime.(*hmap)",
        "runtime.(*bmap)",
        "runtime.(*hiter)",
        "runtime.evacuate",
        "runtime.growWork",
        "runtime.hashGrow",
        "runtime.makeBucketArray",
        "runtime.advanceEvacuationMark",
        "runtime.memhash",
        "runtime.strhash",
        "runtime.aeshash",
        "aeshash",
    ];
    const HASHES: &[&str] = &[
        "runtime.f32hash",
        "runtime.f64hash",
        "runtime.c64hash",
        "runtime.c128hash",
        "runtime.interhash",
        "runtime.nilinterhash",
        "runtime.typehash",
        "runtime.efaceHash",
        "runtime.ifaceHash",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p)) || HASHES.contains(&name)
}

/// A source position resolved for a report PC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLoc {
    pub function: String,
    pub file: String,
    pub line: u32,
    /// The trimmed source line, when the file is readable on this machine.
    pub text: Option<String>,
}

/// Resolve `pcs` to source positions. Tries `go tool addr2line` (Go
/// pclntab) first and binutils `addr2line` (DWARF) second; PCs neither tool
/// resolves are absent from the result.
pub fn source_locations(binary: &str, pcs: &[u64]) -> HashMap<u64, SourceLoc> {
    let mut pcs: Vec<u64> = pcs.iter().copied().filter(|&pc| pc != 0).collect();
    pcs.sort_unstable();
    pcs.dedup();
    if pcs.is_empty() || binary.is_empty() {
        return HashMap::new();
    }
    let input: String = pcs.iter().map(|pc| format!("0x{pc:x}\n")).collect();
    let go_tool = run_with_stdin("go", &["tool", "addr2line", binary], &input);
    let lines = go_tool
        .filter(|out| out.lines().count() >= 2 * pcs.len())
        .or_else(|| {
            let args: Vec<String> = ["-f", "-C", "-e", binary]
                .iter()
                .map(|s| s.to_string())
                .chain(pcs.iter().map(|pc| format!("0x{pc:x}")))
                .collect();
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            run_with_stdin("addr2line", &refs, "")
        });
    let Some(out) = lines else {
        return HashMap::new();
    };
    let out: Vec<&str> = out.lines().collect();
    let mut file_cache: HashMap<String, Option<Vec<String>>> = HashMap::new();
    let mut result = HashMap::new();
    for (i, pc) in pcs.iter().enumerate() {
        let (Some(function), Some(pos)) = (out.get(2 * i), out.get(2 * i + 1)) else {
            break;
        };
        let Some((file, line)) = pos.rsplit_once(':') else {
            continue;
        };
        let line: u32 = line
            .split_whitespace()
            .next()
            .and_then(|l| l.parse().ok())
            .unwrap_or(0);
        if line == 0 || file.starts_with('?') {
            continue;
        }
        let text = file_cache
            .entry(file.to_string())
            .or_insert_with(|| {
                std::fs::read_to_string(file)
                    .ok()
                    .map(|s| s.lines().map(str::to_string).collect())
            })
            .as_ref()
            .and_then(|lines| lines.get(line as usize - 1))
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty());
        result.insert(
            *pc,
            SourceLoc {
                function: function.trim().to_string(),
                file: file.to_string(),
                line,
                text,
            },
        );
    }
    result
}

fn run_with_stdin(program: &str, args: &[&str], input: &str) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }
    let out = child.wait_with_output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_package_paths() {
        assert_eq!(go_package("main.rewriteCSS"), "main");
        assert_eq!(go_package("main.main.func1"), "main");
        assert_eq!(go_package("github.com/a/b.(*T).M"), "github.com/a/b");
        assert_eq!(
            go_package("internal/runtime/maps.(*Map).getWithKey"),
            "internal/runtime/maps"
        );
        assert_eq!(go_package("sync.(*Mutex).Lock"), "sync");
        assert_eq!(go_package("net/http.(*conn).serve"), "net/http");
    }

    #[test]
    fn function_classification() {
        assert!(is_application_function("main.cacheAsset"));
        assert!(is_application_function(
            "example.test/vuln/net/http.(*conn).serve"
        ));
        assert!(!is_application_function("runtime.mapassign_faststr"));
        assert!(!is_application_function("net/http.(*conn).serve"));
        assert!(is_runtime_internal_function("runtime.mallocgc"));
        assert!(is_runtime_internal_function(
            "internal/sync.(*HashTrieMap).Load"
        ));
        assert!(is_runtime_internal_function("sync.(*Mutex).lockSlow"));
        assert!(!is_runtime_internal_function("net/http.(*conn).serve"));
        assert!(!is_runtime_internal_function("main.main"));
        assert!(is_map_internal_function("runtime.mapaccess1_faststr"));
        assert!(is_map_internal_function(
            "internal/runtime/maps.(*table).getWithKey"
        ));
        assert!(is_map_internal_function("runtime.memhash64"));
        assert!(is_map_internal_function("aeshashbody"));
        assert!(!is_map_internal_function("runtime.mallocgc"));
        assert!(!is_map_internal_function("main.rewriteCSS"));
    }

    #[test]
    fn function_lookup_by_pc() {
        let idx = FuncIndex::from_parts(
            vec![
                (0x2000, 0x2100, "main.b".into()),
                (0x1000, 0x1080, "main.a".into()),
                (0x3000, 0x3000, "main.sizeless".into()),
                (0x3400, 0x3500, "main.c".into()),
            ],
            vec![(0x9000, "main.assets".into())],
        );
        assert_eq!(idx.function_at(0x1000).map(|f| f.2), Some("main.a"));
        assert_eq!(idx.function_at(0x107f).map(|f| f.2), Some("main.a"));
        assert_eq!(idx.function_at(0x1080), None);
        assert_eq!(idx.function_at(0x20ff).map(|f| f.2), Some("main.b"));
        assert_eq!(idx.function_at(0x33ff).map(|f| f.2), Some("main.sizeless"));
        assert_eq!(idx.function_at(0xfff), None);
        assert!(idx.has_function("main.c"));
        assert_eq!(idx.pointer_globals()[0].1, "main.assets");
    }
}
