# ReflectivePluginLoader

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A reflective PE mapper, module stomping engine, and **multi-plugin manager** for Windows x64, built around a clean `IPlugin` ABI. Maps DLLs from byte buffers in memory, resolves exports, and calls plugin functions — either from anonymous memory (classic reflective load) or from inside a legitimately loaded sacrificial DLL (module stomping). v2.0.1 adds a `PluginManager` that supports loading multiple plugins concurrently, persistent execution, hot-reload, and a `WinApiTable` abstraction for evasion-layer integration (e.g. KunaiGate/SealApi).

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

### Interactive Mode (v2.0.1)

```powershell
.\harness.exe
```

Launches an interactive menu for runtime plugin management:

```
[1] Load plugin       — pick ID, DLL path, engine (reflective/stomped)
[2] Unload plugin     — by ID
[3] Execute plugin    — by ID, with a command string
[4] Reload plugin     — hot-swap a new DLL into an existing slot
[5] List plugins      — shows count, names, versions, engine type
[6] Execute all       — runs every loaded plugin with one command
[7] Scan commands     — prints pe-sieve/moneta commands for this PID
[q] Quit
```

### CLI Mode

```powershell
# Load multiple plugins and execute them
.\harness.exe --load cmd cmdplugin.dll --load echo echoplugin.dll --exec cmd whoami --exec echo "hello" --list

# Module stomping
.\harness.exe --load cmd cmdplugin.dll --stomp xpsservices.dll --exec cmd whoami

# Hot-reload test (counter resets after reload)
.\harness.exe --load counter counterplugin.dll --exec counter a --exec counter b --reload counter counterplugin.dll --exec counter "after-reload" --list

# Unload
.\harness.exe --load cmd cmdplugin.dll --exec cmd whoami --unload cmd --list --unload-all
```

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
│   ├── ReflectiveLoaderEngine.h       PE mapper + export resolver + FreeImage
│   ├── StompedLoaderEngine.h          Module stomping engine
│   └── PluginManager.h               Multi-plugin lifecycle manager (v2.0.1)
├── Modules/
│   ├── CmdPlugin/
│   │   ├── cmdplugin.cpp              Command execution plugin
│   │   └── CMakeLists.txt
│   ├── EchoPlugin/
│   │   ├── echoplugin.cpp             Echo plugin (demonstrates multi-plugin)
│   │   └── CMakeLists.txt
│   └── CounterPlugin/
│       ├── counterplugin.cpp          Stateful counter (demonstrates persistence)
│       └── CMakeLists.txt
├── Examples/
│   ├── basic_load.cpp                 Minimal single-plugin load + execute
│   ├── multi_plugin.cpp               Multiple plugins with lifecycle
│   ├── hot_reload.cpp                 Hot-reload with CounterPlugin
│   ├── custom_api_table.cpp           Custom WinApiTable with logging wrappers
│   └── module_stomping.cpp            Load via module stomping engine
├── Testing/
│   ├── main.cpp                       Interactive + CLI harness (v2.0.1)
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

4. Optionally export `plugin_info` for metadata:

```cpp
struct PluginInfo { const char* name; const char* version; const char* description; };
extern "C" __declspec(dllexport) PluginInfo __stdcall plugin_info() {
    return { "myplugin", "2.0.2", "My plugin description" };
}
```

5. Add a `CMakeLists.txt` and register it in the root with `add_subdirectory()`.

## Picking a Sacrificial DLL

The sacrificial DLL's `.text` section must be **larger** than the plugin's virtual image size. It should not be actively used by the process or integrity-checked at runtime.

Good candidates: `xpsservices.dll` (1.8 MB .text), `mscms.dll`, `colorui.dll`, `npmproxy.dll`

Bad candidates: `ntdll.dll`, `kernel32.dll` (actively used), `clr.dll` (integrity checked)

## Limitations

- **Supported:** Base relocations, import resolution, per-section protections, contiguous image stomping, full cleanup with page restoration
- **Not supported:** TLS callbacks, delay-load imports, forwarded exports, CFG, SEH table registration
- **Stomping:** The entire plugin virtual image must fit in the sacrificial `.text` section

## What Changed (v2.0.2 — WinApiTable Plumbing)

- **`create_plugin(const WinApiTable* api)`** — plugins now receive the centralized API table at creation time and store it for their entire lifetime
- **`TaskApi.Api`** — execution-time access to the WinApiTable for runtime allocations
- **All plugins updated** — CmdPlugin, EchoPlugin, and CounterPlugin route HeapAlloc/HeapFree through the table; fallback to raw Win32 when `api` is null
- **`Win32.h` included in IPlugin.h** — plugins can reference WinApiTable without extra includes

## What Changed (v2.0.1 — Plugin Manager)

- **PluginManager** (`PluginManager.h`) — multi-plugin lifecycle manager with load, unload, hot-reload, persistent execution, and plugin registry
- **Multiple concurrent plugins** — load N plugins simultaneously, each tracked by a string ID with per-slot SRWLOCK concurrency
- **Persistent execution** — call `execute()` on a loaded plugin multiple times without reloading; plugin instance stays alive until explicit unload
- **Hot-reload** — swap a plugin's DLL at runtime without restarting the process; old instance is torn down, new one initialized at the same slot
- **Plugin metadata** — optional `plugin_info` export for name/version/description; backward-compatible (falls back to caller-supplied ID)
- **WinApiTable abstraction** — all Win API calls (VirtualAlloc, VirtualProtect, LoadLibraryA, etc.) go through a swappable function-pointer table; defaults to raw Win32, swap in KunaiGate/SealApi for evasion-wrapped calls
- **FreeImage()** — proper unload for reflective loads: frees imported module handles and VirtualAlloc'd memory (previously leaked)
- **Import tracking** — `MemModule` now tracks up to 64 imported HMODULEs for clean `FreeLibrary` on unload
- **Sample plugins** — `EchoPlugin` (multi-plugin demo) and `CounterPlugin` (persistence/hot-reload demo)
- **Interactive harness** — runtime menu for load/unload/execute/reload/list; also supports CLI-arg mode for scripted use

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

<img width="1645" height="412" alt="image" src="https://github.com/user-attachments/assets/b1ae769d-5e66-4696-9be8-13b55e569700" />


## References

- [stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [ired.team - Module Stomping](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping)
- [fancycode/MemoryModule](https://github.com/fancycode/MemoryModule)
- [PE Format (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [forrest-orr/moneta](https://github.com/forrest-orr/moneta)
- [hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve)

## License

[MIT](LICENSE)
