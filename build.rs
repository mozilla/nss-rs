// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::unwrap_used,
    clippy::iter_over_hash_type,
    reason = "OK in a build script."
)]

use std::{
    collections::{HashMap, HashSet},
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use bindgen::{
    Builder,
    callbacks::{IntKind, ParseCallbacks},
};
use semver::{Version, VersionReq};
use serde_derive::Deserialize;

const BINDINGS_DIR: &str = "bindings";
const BINDINGS_CONFIG: &str = "bindings.toml";

// The minimum version of NSS that this version of nss-rs requires.
fn min_nss_version() -> String {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest = fs::read_to_string(Path::new(&manifest_dir).join("Cargo.toml")).unwrap();
    let manifest: ::toml::Value = ::toml::from_str(&manifest).unwrap();
    manifest["package"]["metadata"]["nss"]["min-version"]
        .as_str()
        .unwrap()
        .to_owned()
}

// This is the format of a single section of the configuration file.
#[derive(Deserialize)]
struct Bindings {
    /// types that are explicitly included
    #[serde(default)]
    types: Vec<String>,
    /// functions that are explicitly included
    #[serde(default)]
    functions: Vec<String>,
    /// variables (and `#define`s) that are explicitly included
    #[serde(default)]
    variables: Vec<String>,
    /// types that should be explicitly marked as opaque
    #[serde(default)]
    opaque: Vec<String>,
    /// enumerations that are turned into a module (without this, the enum is
    /// mapped using the default, which means that the individual values are
    /// formed with an underscore as <`enum_type`>_<`enum_value_name`>).
    #[serde(default)]
    enums: Vec<String>,

    /// Any item that is specifically excluded; if none of the types, functions,
    /// or variables fields are specified, everything defined will be mapped,
    /// so this can be used to limit that.
    #[serde(default)]
    exclude: Vec<String>,

    /// Whether the file is to be interpreted as C++
    #[serde(default)]
    cplusplus: bool,
}

impl Bindings {
    fn check_sorted(&self, name: &str) {
        for (field, values) in [
            ("types", &self.types),
            ("functions", &self.functions),
            ("variables", &self.variables),
            ("opaque", &self.opaque),
            ("enums", &self.enums),
            ("exclude", &self.exclude),
        ] {
            if let Some((a, b)) = values
                .iter()
                .zip(values.iter().skip(1))
                .find(|(a, b)| a >= b)
            {
                panic!("{name}.{field} is not sorted (or has duplicates): {a:?} >= {b:?}");
            }
        }
    }
}

// bindgen needs access to libclang.
// On windows, this doesn't just work, you have to set LIBCLANG_PATH.
// Rather than download the 400Mb+ files, like gecko does, let's just reuse their work.
// On macOS, clang-sys prefers the highest-versioned libclang it can find, which may be a
// Homebrew LLVM that doesn't have the correct macOS SDK include paths, resulting in broken
// bindings. Force use of Xcode's libclang instead.
fn setup_clang() {
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
    println!("cargo:rerun-if-env-changed=CI");
    // In CI, the environment is already configured correctly.
    if env::var("CI").is_ok() {
        return;
    }
    if env::var("LIBCLANG_PATH").is_ok() {
        return;
    }
    if env::consts::OS == "macos" {
        if let Ok(output) = Command::new("xcode-select").arg("--print-path").output() {
            if output.status.success() {
                let xcode_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let candidates = [
                    PathBuf::from(&xcode_path).join("Toolchains/XcodeDefault.xctoolchain/usr/lib"),
                    PathBuf::from(&xcode_path).join("usr/lib"),
                ];
                if let Some(libclang_dir) = candidates.iter().find(|p| p.is_dir()) {
                    unsafe {
                        env::set_var("LIBCLANG_PATH", libclang_dir.to_str().unwrap());
                    }
                } else {
                    println!(
                        "cargo:warning=Xcode toolchain libclang not found at {}; set LIBCLANG_PATH if build fails",
                        candidates[0].display()
                    );
                }
            } else {
                println!(
                    "cargo:warning=xcode-select returned an error; set LIBCLANG_PATH if build fails"
                );
            }
        } else {
            println!("cargo:warning=xcode-select not found; set LIBCLANG_PATH if build fails");
        }
    } else if env::consts::OS == "windows" {
        println!("cargo:rerun-if-env-changed=MOZBUILD_STATE_PATH");
        let mozbuild_root = if let Ok(dir) = env::var("MOZBUILD_STATE_PATH") {
            PathBuf::from(dir.trim())
        } else {
            println!("cargo:warning=Building without a gecko setup is not likely to work.");
            println!("cargo:warning=A working libclang is needed to build nss-rs.");
            println!("cargo:warning=Either LIBCLANG_PATH or MOZBUILD_STATE_PATH needs to be set.");
            println!(
                "cargo:warning=We recommend checking out https://github.com/mozilla/gecko-dev"
            );
            println!("cargo:warning=Then run `./mach bootstrap` which will retrieve clang.");
            println!("cargo:warning=Make sure to export MOZBUILD_STATE_PATH when building.");
            return;
        };
        let libclang_dir = mozbuild_root.join("clang").join("lib");
        if libclang_dir.is_dir() {
            unsafe {
                env::set_var("LIBCLANG_PATH", libclang_dir.to_str().unwrap());
            }
        } else {
            println!(
                "cargo:warning=LIBCLANG_PATH isn't set; maybe run ./mach bootstrap with gecko"
            );
        }
    }
}

fn nss_dir() -> String {
    let dir = env::var("NSS_DIR").map_or_else(
        |_| {
            let out_dir = env::var("OUT_DIR").unwrap();
            let dir = Path::new(&out_dir).join("nss");
            if !dir.exists() {
                Command::new("hg")
                    .args([
                        "clone",
                        "https://hg.mozilla.org/projects/nss",
                        dir.to_str().unwrap(),
                    ])
                    .status()
                    .expect("can't clone nss");
            }
            let nspr_dir = Path::new(&out_dir).join("nspr");
            if !nspr_dir.exists() {
                Command::new("hg")
                    .args([
                        "clone",
                        "https://hg.mozilla.org/projects/nspr",
                        nspr_dir.to_str().unwrap(),
                    ])
                    .status()
                    .expect("can't clone nspr");
            }
            dir
        },
        |dir| {
            let path = PathBuf::from(dir.trim());
            assert!(
                !path.is_relative(),
                "The NSS_DIR environment variable is expected to be an absolute path."
            );
            path
        },
    );
    assert!(dir.is_dir(), "NSS_DIR {} doesn't exist", dir.display());
    // Note that this returns a relative path because UNC
    // paths on windows cause certain tools to explode.
    dir.to_string_lossy().to_string()
}

fn get_bash() -> PathBuf {
    // If BASH is set, use that.
    if let Ok(bash) = env::var("BASH") {
        return PathBuf::from(bash);
    }

    // When running under MOZILLABUILD, we need to make sure not to invoke
    // another instance of bash that might be sitting around (like WSL).
    env::var("MOZILLABUILD").map_or_else(
        |_| PathBuf::from("bash"),
        |d| PathBuf::from(d).join("msys").join("bin").join("bash.exe"),
    )
}

fn build_nss(dir: PathBuf) {
    let mut build_nss = vec![
        String::from("./build.sh"),
        String::from("-Ddisable_tests=1"),
        String::from("-Ddisable_dbm=1"),
        String::from("-Ddisable_libpkix=1"),
        String::from("-Ddisable_ckbi=1"),
        String::from("-Ddisable_fips=1"),
        String::from("--opt"),
        // Generate static libraries in addition to shared libraries.
        String::from("--static"),
    ];
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "aarch64" {
        build_nss.push(String::from("--target=arm64"));
    }
    let status = Command::new(get_bash())
        .args(build_nss)
        .current_dir(dir)
        .status()
        .expect("couldn't start NSS build");
    assert!(status.success(), "NSS build failed");
}

/// A library name without the `lib` prefix or any extension, so that the names we link and
/// the files on disk can be compared: `nss3` for `nss3`, `libnss3.so.3` and `nss3.dll`.
fn lib_stem(name: &str) -> &str {
    let name = name.strip_prefix("lib").unwrap_or(name);
    name.split_once('.').map_or(name, |(stem, _)| stem)
}

/// Emit the link search path for `dir`, and re-run the build script when any of `libs`
/// found there changes or goes away.
///
/// Naming the library files rather than `dir` keeps Cargo from scanning a shared system
/// library directory recursively on every freshness check.  Only files that are present are
/// named, because a path that is already absent makes Cargo treat the script as dirty on
/// every later build.
fn link_search<S: AsRef<str>>(dir: &Path, libs: &[S]) {
    println!("cargo:rustc-link-search=native={}", dir.display());
    let wanted: HashSet<&str> = libs.iter().map(|l| lib_stem(l.as_ref())).collect();
    let Ok(entries) = fs::read_dir(dir) else {
        println!(
            "cargo:warning=can't read {}, so NSS changes there won't trigger a rebuild",
            dir.display()
        );
        return;
    };
    for entry in entries.flatten() {
        let (name, path) = (entry.file_name(), entry.path());
        let (Some(name), Some(path)) = (name.to_str(), path.to_str()) else {
            continue;
        };
        if !path.contains('\n') && wanted.contains(lib_stem(name)) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

fn dynamic_link() -> Vec<String> {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let dynamic_libs = if target_os == "windows" {
        [
            "nssutil3.dll",
            "nss3.dll",
            "ssl3.dll",
            "libplds4.dll",
            "libplc4.dll",
            "libnspr4.dll",
        ]
    } else {
        ["nssutil3", "nss3", "ssl3", "plds4", "plc4", "nspr4"]
    };
    for lib in dynamic_libs {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }
    dynamic_libs
        .into_iter()
        .chain(maybe_link_freebl3())
        .map(String::from)
        .collect()
}

fn maybe_link_freebl3() -> Option<&'static str> {
    if env::var("CARGO_FEATURE_BLAPI").is_ok() {
        println!("cargo:rustc-link-lib=dylib=freebl3");
        return Some("freebl3");
    }
    None
}

/// The archives in `lib_dir`: `nss_static` for `libnss_static.a` and `nss_static.lib`.
///
/// On Windows this also picks up import libraries: `nss3.dll` from `nss3.dll.lib`, which
/// [`installed_static_libs`] drops, and NSPR's `libnspr4`, which [`resolve_archive`] asks
/// for on purpose.
fn installed_archives(lib_dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(lib_dir) else {
        return Vec::new();
    };
    let mut libs: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|file| {
            if let Some(name) = file.strip_suffix(".lib") {
                // MSVC has no `lib` prefix convention, so a name that carries one
                // there is part of the library's name, as it is for NSPR.
                return Some(name.to_owned());
            }
            let name = file.strip_suffix(".a")?;
            Some(name.strip_prefix("lib").unwrap_or(name).to_owned())
        })
        .collect();
    libs.sort_unstable();
    libs.dedup();
    libs
}

/// The `-l` names a system pkg-config reports for `module`, for a requirement the
/// dist does not describe itself.
///
/// `build.sh --with-nspr`/`--system-nspr` installs no `nspr.pc` beside the
/// archives, yet still writes `Requires: nspr` into `nss-static.pc`. The system
/// NSPR that satisfies it brings its own `.pc`, so ask for it the usual way.
///
/// `None` where there is no pkg-config to run, which is every target that made
/// the in-tree parser necessary in the first place.
fn system_pkg_config_libs(module: &str) -> Option<Vec<String>> {
    // A cross build's pkg-config is a different binary, named by `PKG_CONFIG`.
    let pkg_config = env::var("PKG_CONFIG").unwrap_or_else(|_| String::from("pkg-config"));
    let output = Command::new(pkg_config)
        .args(["--libs-only-l", "--static", module])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let libs = String::from_utf8(output.stdout).ok()?;
    Some(
        libs.split_whitespace()
            .filter_map(|flag| flag.strip_prefix("-l"))
            .map(String::from)
            .collect(),
    )
}

/// The module names in the pkg-config `Requires:` field without version constraints.
///
/// A constraint needs no surrounding space, so `nspr >= 4.40`, `nspr >=4.40` and
/// `nspr>=4.40` all name just `nspr`.
fn required_modules(field: &str) -> Vec<String> {
    let mut modules = Vec::new();
    let mut skip_version = false;
    for token in field.split([',', ' ', '\t']).filter(|t| !t.is_empty()) {
        if std::mem::take(&mut skip_version) {
            continue;
        }
        let Some(op) = token.find(['<', '>', '=', '!']) else {
            modules.push(token.to_owned());
            continue;
        };
        if op > 0 {
            modules.push(token[..op].to_owned());
        }
        // The version follows the operator, unless the token ends at it.
        skip_version = token[op..]
            .trim_start_matches(['<', '>', '=', '!'])
            .is_empty();
    }
    modules
}

/// The `-l` names in `<module>.pc`, then those of everything it requires.
///
/// Not pkg-config: resolves modules within `pc_dir` only, and reads only `Libs`,
/// `Libs.private` and `Requires`. `-L` is `${libdir}`, which the caller already
/// searches. Shelling out to the real thing would give us variable expansion and
/// `Requires` for free, but it is not there to shell out to on the Windows and
/// Android builds that need this.
///
/// Each module is emitted once, at its first mention, which for a graph deeper
/// than NSS's `nss-static` -> `nspr` need not be a correct link order.
fn pkg_config_libs(pc_dir: &Path, module: &str, seen: &mut HashSet<String>) -> Option<Vec<String>> {
    if !seen.insert(module.to_owned()) {
        return Some(Vec::new());
    }
    let path = pc_dir.join(format!("{module}.pc"));
    let text = fs::read_to_string(&path).ok()?;
    println!("cargo:rerun-if-changed={}", path.display());

    let mut libs = Vec::new();
    let mut requires = Vec::new();
    for line in text.lines() {
        // Fields are `Name: value`. A variable definition can hold a colon too,
        // in a Windows drive letter, but its key matches no field below.
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "libs" | "libs.private" => libs.extend(
                value
                    .split_whitespace()
                    .filter_map(|flag| flag.strip_prefix("-l"))
                    .map(String::from),
            ),
            "requires" | "requires.private" => requires.extend(required_modules(value)),
            _ => {}
        }
    }
    // A required module is a dependency, so it links last.
    for required in requires {
        let Some(required_libs) =
            pkg_config_libs(pc_dir, &required, seen).or_else(|| system_pkg_config_libs(&required))
        else {
            // Keep what this file did describe. Discarding it would fall back to
            // guessing from the installed archives, which for the case that gets
            // here - `--system-nspr`, which writes the requirement but installs
            // neither the `.pc` nor the archives - cannot supply the module either.
            println!(
                "cargo:warning=no {}, required by {module}.pc, and pkg-config \
                 could not supply it; linking without it",
                pc_dir.join(format!("{required}.pc")).display()
            );
            continue;
        };
        libs.extend(required_libs);
    }
    Some(libs)
}

/// The libraries to link, in link order, as `nss-static.pc` names them.
///
/// `build.sh --static` derives that from the gyp graph of the build it just did,
/// so it matches how this NSS actually splits into archives. NSPR is not in that
/// graph and arrives through `Requires: nspr`.
///
/// `None` when there is no such file, which at our minimum NSS version means a
/// dist that `build.sh --static` did not produce; see [`installed_static_libs`].
fn pkg_config_static_libs(lib_dir: &Path) -> Option<Vec<String>> {
    pkg_config_libs(
        &lib_dir.join("pkgconfig"),
        "nss-static",
        &mut HashSet::new(),
    )
}

/// The libraries to link, guessed from the `archives` that are installed, for a
/// dist that has no `nss-static.pc`.
///
/// Only Android gets here. Its NSS comes from application-services'
/// `build-nss-android.sh`, which drives gyp directly and so never runs the
/// `build.sh` that writes the file. That dist is a hand-picked set of archives,
/// which is the case this guessing handles well.
///
/// Take whatever is installed and drop what would define a symbol twice:
///
/// - `<x>` shadowed by `<x>_static`, the copy built for the shared library.
/// - `<x>_s` shadowed by `<x>`, NSPR's static build where its import library is also installed.
///   That ordering matches [`resolve_archive`], and for the same reason: a `--static` NSS still
///   compiles against NSPR as a DLL.
/// - `*-nodepend*`, freebl's `FREEBL_NO_DEPEND` variants.
/// - `*-testlib`, which duplicates what it tests.
/// - `<x>.dll`, from a `<x>.dll.lib` import library, which the `_static` archives replace.
///
/// The rest is inert, as an unreferenced archive member is never pulled into the link.
fn installed_static_libs(archives: &[String]) -> Vec<String> {
    let installed: HashSet<&str> = archives.iter().map(String::as_str).collect();
    let shadowed: HashSet<&str> = archives
        .iter()
        .filter_map(|lib| lib.strip_suffix("_static"))
        .collect();
    archives
        .iter()
        .filter(|lib| {
            !shadowed.contains(lib.as_str())
                && !lib.contains("-nodepend")
                && !lib.ends_with("-testlib")
                && !Path::new(lib.as_str())
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("dll"))
                && !lib
                    .strip_suffix("_s")
                    .is_some_and(|plain| installed.contains(plain))
        })
        .cloned()
        .collect()
}

/// The archive among `archives` that a `.pc`'s `-l<name>` refers to, if NSS
/// installed one.
///
/// A `.pc` spells library names the Unix way, but MSVC has no `lib` prefix
/// convention, so `nspr.pc` asks for `-lnspr4` where the file is `libnspr4.lib`.
///
/// NSPR also installs a `_s` archive, and that is deliberately the last resort:
/// on Windows even a `--static` NSS compiles against NSPR as a DLL, so its
/// objects want the `__imp_` symbols that only the import library defines.
/// Linking `libnspr4_s.lib` to satisfy `-lnspr4` leaves those undefined.
fn resolve_archive<'a>(archives: &'a HashSet<String>, name: &str) -> Option<&'a String> {
    [
        name.to_owned(),
        format!("lib{name}"),
        format!("{name}_s"),
        format!("lib{name}_s"),
    ]
    .iter()
    .find_map(|candidate| archives.get(candidate))
}

fn static_link(lib_dir: &Path) -> Vec<String> {
    let installed = installed_archives(lib_dir);
    let mut named = pkg_config_static_libs(lib_dir)
        // One that names nothing is no better than no file at all.
        .filter(|libs| !libs.is_empty())
        .unwrap_or_else(|| installed_static_libs(&installed));
    assert!(
        !named.is_empty(),
        "nothing to link in {}; is this an NSS built with --static?",
        lib_dir.display()
    );
    let archives: HashSet<String> = installed.into_iter().collect();
    // macOS always dynamically links against the system sqlite library, so NSS
    // builds no copy of its own there for the .pc to name.
    // See https://github.com/nss-dev/nss/blob/a8c22d8fc0458db3e261acc5e19b436ab573a961/coreconf/Darwin.mk#L130-L135
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "macos" {
        named.push(String::from("sqlite3"));
    }
    // Return what was linked, not what the .pc called it, so that `link_search`
    // can find the files again.
    named
        .iter()
        .map(|name| {
            resolve_archive(&archives, name).map_or_else(
                || {
                    // Whatever NSS didn't build here has to come from the system.
                    println!("cargo:rustc-link-lib=dylib={name}");
                    name.clone()
                },
                |archive| {
                    println!("cargo:rustc-link-lib=static={archive}");
                    archive.clone()
                },
            )
        })
        .collect()
}

fn get_includes(nsstarget: &Path, nssdist: &Path) -> Vec<PathBuf> {
    let nsprinclude = nsstarget.join("include").join("nspr");
    let nssinclude = nssdist.join("public").join("nss");
    vec![nsprinclude, nssinclude]
}

/// Type PKCS#11 `#define`s as the `CK_*` typedefs they belong to. Bindgen otherwise picks the
/// smallest integer that fits the value, which needs a conversion at every use.
#[derive(Debug)]
struct Pkcs11Types;

impl ParseCallbacks for Pkcs11Types {
    fn int_macro(&self, name: &str, _: i64) -> Option<IntKind> {
        // `CKD_*` gets CK_ULONG because CK_EC_KDF_TYPE isn't among the generated types, and
        // that is what PK11_PubDeriveWithKDF's `kdf` parameter is declared as anyway.
        let name = match name {
            "CK_INVALID_HANDLE" => "CK_OBJECT_HANDLE",
            n if n.starts_with("CKA_") => "CK_ATTRIBUTE_TYPE",
            n if n.starts_with("CKF_") => "CK_FLAGS",
            n if n.starts_with("CKG_") => "CK_GENERATOR_FUNCTION",
            n if n.starts_with("CKM_") => "CK_MECHANISM_TYPE",
            n if n.starts_with("CKD_") || n.starts_with("CK_") => "CK_ULONG",
            _ => return None,
        };
        Some(IntKind::Custom {
            name,
            is_signed: false,
        })
    }
}

fn build_bindings(base: &str, bindings: &Bindings, flags: &[String], gecko: bool) {
    let suffix = if bindings.cplusplus { ".hpp" } else { ".h" };
    let header_path = PathBuf::from(BINDINGS_DIR).join(String::from(base) + suffix);
    let header = header_path.to_str().unwrap();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(String::from(base) + ".rs");

    println!("cargo:rerun-if-changed={header}");

    let mut builder = Builder::default().header(header);
    builder = builder.generate_comments(false);
    builder = builder.size_t_is_usize(true);
    if base == "nss_p11" {
        builder = builder.parse_callbacks(Box::new(Pkcs11Types));
    }

    builder = builder.clang_arg("-v");

    if !gecko {
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
        builder = builder.clang_arg("-DNO_NSPR_10_SUPPORT");
        if target_os == "windows" {
            builder = builder.clang_arg("-DWIN");
        } else if target_os == "macos" {
            builder = builder.clang_arg("-DDARWIN");
        } else if target_os == "linux" {
            builder = builder.clang_arg("-DLINUX");
        } else if target_os == "android" {
            builder = builder.clang_arg("-DLINUX");
            builder = builder.clang_arg("-DANDROID");
        }
        if bindings.cplusplus {
            builder = builder.clang_args(["-x", "c++", "-std=c++14"]);
        }
    }

    builder = builder.clang_args(flags);

    // Apply the configuration.
    for v in &bindings.types {
        builder = builder.allowlist_type(v);
    }
    for v in &bindings.functions {
        builder = builder.allowlist_function(v);
    }
    for v in &bindings.variables {
        builder = builder.allowlist_var(v);
    }
    for v in &bindings.exclude {
        builder = builder.blocklist_item(v);
    }
    for v in &bindings.opaque {
        builder = builder.opaque_type(v);
    }
    for v in &bindings.enums {
        builder = builder.constified_enum_module(v);
    }

    let bindings = builder.generate().expect("unable to generate bindings");
    bindings
        .write_to_file(out)
        .expect("couldn't write bindings");
}

fn pkg_config(min_version: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let modversion = Command::new("pkg-config")
        .args(["--modversion", "nss"])
        .output()?
        .stdout;

    let modversion = String::from_utf8(modversion)?;

    let modversion = modversion.trim();

    // The NSS version number does not follow semver numbering, because it omits the patch version
    // when that's 0. Deal with that.
    let modversion_for_cmp = if modversion.chars().filter(|c| *c == '.').count() == 1 {
        modversion.to_owned() + ".0"
    } else {
        modversion.to_owned()
    };

    let modversion_for_cmp = Version::parse(&modversion_for_cmp)?;

    let version_req = VersionReq::parse(&format!(">={min_version}"))?;

    assert!(
        version_req.matches(&modversion_for_cmp),
        "nss-rs has NSS version requirement {version_req}, found {modversion}",
    );

    let cfg = Command::new("pkg-config")
        .args(["--cflags", "--libs", "nss"])
        .output()?
        .stdout;

    let cfg_str = String::from_utf8(cfg)?;

    let mut flags: Vec<String> = Vec::new();
    let mut lib_dirs: Vec<PathBuf> = Vec::new();
    let mut libs: Vec<&str> = Vec::new();

    for f in cfg_str.split_whitespace() {
        if f.starts_with("-I") {
            flags.push(String::from(f));
        } else if let Some(path) = f.strip_prefix("-L") {
            lib_dirs.push(PathBuf::from(path));
        } else if let Some(lib) = f.strip_prefix("-l") {
            println!("cargo:rustc-link-lib=dylib={lib}");
            libs.push(lib);
        } else {
            println!("cargo:warning=Unknown flag from pkg-config: {f}");
        }
    }

    if env::var("CARGO_FEATURE_BLAPI").is_ok() {
        // pkg-config omits -L for default system library paths (e.g., /usr/lib64 on
        // RHEL/Fedora), so also include the libdir from the .pc file.
        if let Ok(output) = Command::new("pkg-config")
            .args(["--variable=libdir", "nss"])
            .output()
            && output.status.success()
            && let Ok(s) = String::from_utf8(output.stdout)
        {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                let dir = PathBuf::from(trimmed);
                if !lib_dirs.contains(&dir) {
                    lib_dirs.push(dir);
                }
            }
        }
    }
    libs.extend(maybe_link_freebl3());

    for dir in &lib_dirs {
        link_search(dir, &libs);
    }

    Ok(flags)
}

fn setup_standalone(nss_dir: String) -> Vec<String> {
    let nss = PathBuf::from(nss_dir);

    // $NSS_DIR/../dist/
    let nssdist = nss.parent().unwrap().join("dist");
    let nsstarget = "Release";

    // If NSS_PREBUILT is set to a non-zero value, we assume that the NSS libraries are already
    // built.
    if !env::var("NSS_PREBUILT").is_ok_and(|v| v != "0") {
        build_nss(nss);
    }

    let nsstarget = nssdist.join(nsstarget);
    let includes = get_includes(&nsstarget, &nssdist);

    let nsslibdir = nsstarget.join("lib");
    let libs = if env::var("CARGO_CFG_FUZZING").is_ok()
        || env::var("PROFILE").unwrap_or_default() == "debug"
        // FIXME: NSPR doesn't build proper dynamic libraries on Windows.
        || env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows"
    {
        static_link(&nsslibdir)
    } else {
        dynamic_link()
    };
    link_search(&nsslibdir, &libs);

    let mut flags: Vec<String> = Vec::new();
    for i in includes {
        flags.push(String::from("-I") + i.to_str().unwrap());
    }

    flags
}

#[cfg(feature = "gecko")]
fn setup_for_gecko() -> Vec<String> {
    use mozbuild::{
        TOPOBJDIR,
        config::{BINDGEN_SYSTEM_FLAGS, NSPR_CFLAGS, NSS_CFLAGS},
    };

    let fold_libs = mozbuild::config::MOZ_FOLD_LIBS;
    let libs = if fold_libs {
        vec!["nss3"]
    } else {
        vec!["nssutil3", "nss3", "ssl3", "plds4", "plc4", "nspr4"]
    };

    for lib in &libs {
        println!("cargo:rustc-link-lib=dylib={}", lib);
    }

    let lib_dirs = if fold_libs {
        vec![TOPOBJDIR.join("security")]
    } else {
        let nsslib_path = TOPOBJDIR.join("security").join("nss").join("lib");
        vec![
            TOPOBJDIR.join("dist").join("bin"),
            nsslib_path.join("nss").join("nss_nss3"),
            nsslib_path.join("ssl").join("ssl_ssl3"),
            TOPOBJDIR
                .join("config")
                .join("external")
                .join("nspr")
                .join("pr"),
        ]
    };
    for dir in &lib_dirs {
        link_search(dir, &libs);
    }

    let mut flags = BINDGEN_SYSTEM_FLAGS
        .iter()
        .chain(&NSPR_CFLAGS)
        .chain(&NSS_CFLAGS)
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    flags.push(String::from("-include"));
    flags.push(
        TOPOBJDIR
            .join("dist")
            .join("include")
            .join("mozilla-config.h")
            .to_str()
            .unwrap()
            .to_string(),
    );
    flags
}

#[cfg(not(feature = "gecko"))]
fn setup_for_gecko() -> Vec<String> {
    unreachable!()
}

fn process_config(config: &mut HashMap<String, Bindings>) {
    for (n, b) in config.iter() {
        b.check_sorted(n);
    }

    let names = config.keys().cloned().collect::<Vec<_>>();
    for name in names {
        // Collect the list of types, functions, and variables configured
        // for generation in any other configured header, and add it to the list
        // of items excluded from generation in this header. This ensures that
        // each item only appears in one bindings module, which prevents some
        // type conflicts. (However, it does mean that appropriate `use`
        // declarations must be added for the generated modules.)
        let excl = config
            .iter()
            .filter(|(n, _)| **n != name)
            .flat_map(|(_, b)| [&b.types, &b.functions, &b.variables])
            .flatten()
            .cloned()
            .collect::<Vec<_>>();

        config
            .get_mut(&name)
            .expect("key disappeared from config?") // impossible
            .exclude
            .extend(excl);
    }

    for b in config.values_mut() {
        b.exclude.sort_unstable();
        b.exclude.dedup();
    }
}

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rustc-check-cfg=cfg(nss_nodb)");

    let config_file = PathBuf::from(BINDINGS_DIR).join(BINDINGS_CONFIG);
    println!("cargo:rerun-if-changed={}", config_file.to_str().unwrap());
    let config = fs::read_to_string(config_file).expect("unable to read binding configuration");
    let mut config: HashMap<String, Bindings> = ::toml::from_str(&config).unwrap();
    process_config(&mut config);

    setup_clang();

    let min_version = min_nss_version();
    println!("cargo:rustc-env=NSS_MIN_VERSION={min_version}");

    // These select which NSS installation is used, or which flags pkg-config reports.
    for var in [
        "NSS_DIR",
        "NSS_PREBUILT",
        "PKG_CONFIG",
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_LIBDIR",
        "PKG_CONFIG_SYSROOT_DIR",
        "PKG_CONFIG_SYSTEM_LIBRARY_PATH",
        "PKG_CONFIG_SYSTEM_INCLUDE_PATH",
        "PKG_CONFIG_ALLOW_SYSTEM_LIBS",
        "PKG_CONFIG_ALLOW_SYSTEM_CFLAGS",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let flags = if cfg!(feature = "gecko") {
        setup_for_gecko()
    } else if let Ok(nss_dir) = env::var("NSS_DIR") {
        setup_standalone(nss_dir.trim().to_string())
    } else {
        pkg_config(&min_version).unwrap_or_else(|_| setup_standalone(nss_dir()))
    };

    for (k, v) in &config {
        build_bindings(k, v, &flags[..], cfg!(feature = "gecko"));
    }
}
