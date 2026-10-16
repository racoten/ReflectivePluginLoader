# ReflectivePluginLoader

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A minimal reflective PE mapper and module stomping engine for Windows x64, built around a clean `IPlugin` ABI. Maps a DLL from a byte buffer in memory, resolves exports, and calls plugin functions — either from anonymous memory (classic reflective load) or from inside a legitimately loaded sacrificial DLL (module stomping).

The module stomping path is **evasion-hardened**: per-section protections (no RWX), private mapping cleanup, original byte restoration, and heap scrubbing. Post-cleanup scans with pe-sieve, Moneta, hollows_hunter, BeaconEye, and YARA return zero findings on the stomped module.

## Quick Start

Requires CMake 3.15+ and either MSVC, Clang, or MinGW on Windows.

```powershell
# Configure (defaults to Release)
cmake -B build -G Ninja

# Build
cmake --build build

# The build produces:
#   build/Modules/CmdPlugin/cmdplugin.dll   (example plugin)
#   build/Testing/harness.exe               (test harness)
```

For a Debug build with full diagnostic output:

```powershell
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Usage

### Classic Reflective Load

```powershell
.\harness.exe cmdplugin.dll whoami
```

Maps the plugin into `VirtualAlloc`'d memory. No PEB entry, no loader notification.

### Module Stomping

```powershell
.\harness.exe cmdplugin.dll whoami --stomp xpsservices.dll
.\harness.exe cmdplugin.dll "dir C:\" --stomp mscms.dll
```

Loads the sacrificial DLL legitimately via `LoadLibrary`, then overwrites its `.text` with the plugin as a contiguous image. Execution happens from the sacrificial DLL's address space — call stacks and module lists attribute the code to the sacrificial module.

The harness pauses after cleanup so you can run memory scanners against the process.

## How Module Stomping Works

```
1. MapImage(plugin)               private reflective mapping
2. LoadLibrary(sacrificial)       legitimate load, PEB entry
3. Save original .text bytes      for later restoration
4. Copy plugin image -> .text     contiguous image preserves RIP-relative offsets
5. Relocate stomped code          fix addresses for new base
6. Patch entry point              mov eax,1; ret (safe FreeLibrary)
7. Per-section protections        RX / R / RW per section (never RWX)
8. Resolve exports                from private mapping, return stomped addresses
9. Free private mapping           eliminates floating PE artifact
10. Execute plugin                code runs inside "sacrificial.dll"
```

### Cleanup (Evasion)

```
11. Restore original .text bytes  sacrificial code back in place
12. FreeLibrary(sacrificial)      unloads the module
13. LoadLibrary(sacrificial)      fresh load = clean file-backed pages
14. Scrub heap buffers            zero saved bytes + raw DLL data
```

After cleanup, the sacrificial DLL is indistinguishable from a normally loaded module. Pages are file-backed (not private), content matches the on-disk file, and no PE artifacts remain on the heap.

## Evasion Techniques

| IOC | Mitigation |
|---|---|
| RWX memory regions | Per-section protections: `.text` RX, `.rdata` R, `.data` RW |
| Private executable memory (floating PE) | `VirtualFree` the private mapping after export resolution |
| Modified module code | Restore original `.text` bytes, then `FreeLibrary` + `LoadLibrary` for clean file-backed pages |
| PE headers on heap | `memset(0)` raw DLL buffer and saved bytes before freeing |
| DllMain crash on unload | Entry point patched to `mov eax,1; ret` before stomping |

## Project Structure

```
ReflectivePluginLoader/
├── CMakeLists.txt
├── Include/
│   ├── IPlugin.h                      Plugin ABI (TaskApi, IPlugin)
│   ├── ReflectiveLoaderEngine.h       PE mapper + export resolver
│   └── StompedLoaderEngine.h          Module stomping engine
├── Modules/
│   └── CmdPlugin/
│       ├── cmdplugin.cpp              Command execution plugin
│       └── CMakeLists.txt
├── Testing/
│   ├── main.cpp                       Test harness
│   └── CMakeLists.txt
└── Tools/
    └── file2hex.py                    DLL to C byte array converter
```

## Writing a Plugin

1. Create a directory under `Modules/` and include `IPlugin.h`.
2. Implement the `IPlugin` interface:

```cpp
#include "IPlugin.h"

class MyPlugin : public IPlugin {
public:
    void init()                  const override { /* setup */ }
    void execute(TaskApi* task)  const override { /* work  */ }
    void cleanup()               const override { /* tear  */ }
};
```

3. Export the five entry points (`create_plugin`, `destroy_plugin`, `plugin_init`, `plugin_exec`, `plugin_cleanup`). Use `HeapAlloc` + placement `new` for CRT-safe allocation.

4. Add a `CMakeLists.txt` and register it in the root with `add_subdirectory()`.

## Picking a Sacrificial DLL

The sacrificial DLL's `.text` section must be **larger** than the plugin's virtual image size. It should not be actively used by the process or integrity-checked at runtime.

Good candidates: `xpsservices.dll` (1.8 MB .text), `mscms.dll`, `colorui.dll`, `npmproxy.dll`

Bad candidates: `ntdll.dll`, `kernel32.dll` (actively used), `clr.dll` (integrity checked)

## Limitations

- **Supported:** Base relocations, import resolution, per-section protections, contiguous image stomping, full cleanup with page restoration
- **Not supported:** TLS callbacks, delay-load imports, forwarded exports, CFG, SEH table registration
- **Stomping:** The entire plugin virtual image must fit in the sacrificial `.text` section

## What Changed (v2.0 — Evasion Hardening)

This release is a ground-up rewrite of the original proof-of-concept:

- **Module stomping engine** (`StompedLoaderEngine.h`) — contiguous image stomping with full evasion cleanup
- **Per-section memory protections** — `.text` RX, `.rdata` R, `.data` RW; no more RWX regions
- **Private page elimination** — `FreeLibrary` + `LoadLibrary` cycle replaces privatized pages with clean file-backed ones
- **Heap scrubbing** — raw DLL bytes and saved original `.text` are zeroed before the scan window
- **Entry point patching** — `mov eax,1; ret` prevents DllMain crash during `FreeLibrary`
- **Private mapping cleanup** — `VirtualFree` the reflective mapping after export resolution (eliminates floating PE)
- **Reflective loader rewrite** (`ReflectiveLoaderEngine.h`) — direct mapping from input buffer, no intermediate `VirtualAlloc` copy
- **Plugin ABI cleanup** (`IPlugin.h`) — removed dead helpers (`BeaconCout`, `CStrLenA`, `PluginAlloc`, `PluginFree`)
- **CmdPlugin cleanup** — removed all marker strings and debug artifacts
- **Test harness rewrite** (`main.cpp`) — conditional compilation via `NDEBUG`; Release builds show only command output and scan commands
- **CMake defaults** — Release build type by default, `-nostartfiles` for plugin DLLs (no CRT in reflective-loaded code)

### Scanner Results (post-cleanup)

| Scanner | Result |
|---|---|
| pe-sieve | CLEAN |
| Moneta | CLEAN (unsigned exe only — not a stomping IOC) |
| hollows_hunter | CLEAN |
| BeaconEye | CLEAN |
| YARA (CobaltStrike rules) | CLEAN |
| Hunt-Sleeping-Beacons | CLEAN |
| Patriot | CLEAN |
| MalMemDetect | CLEAN |

Tested with [GrumpySuite](https://github.com/racoten/GrumpySuite) (17-scanner aggregator).

## References

- [stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [ired.team - Module Stomping](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping)
- [fancycode/MemoryModule](https://github.com/fancycode/MemoryModule)
- [PE Format (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [forrest-orr/moneta](https://github.com/forrest-orr/moneta)
- [hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve)

## License

[MIT](LICENSE)
