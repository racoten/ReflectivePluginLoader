# ReflectivePluginLoader

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A reflective PE mapper, module stomping engine, and **multi-plugin manager** for Windows x64, built around a clean `IPlugin` ABI. Maps DLLs from byte buffers in memory, resolves exports, and calls plugin functions — either from anonymous memory (classic reflective load) or from inside a legitimately loaded sacrificial DLL (module stomping). Includes a `PluginManager` for concurrent plugins, hot-reload, a `WinApiTable` abstraction for evasion-layer integration, and a unified sleep mask module with two-process beacon architecture.

The module stomping path is **evasion-hardened**: per-section protections (no RWX), private mapping cleanup, original byte restoration, and heap scrubbing. Post-cleanup scans with pe-sieve, Moneta, hollows_hunter, BeaconEye, and YARA return zero findings on the stomped module.

## Quick Start

Requires CMake 3.15+ and either MSVC, Clang, or MinGW on Windows.

```powershell
# Configure (defaults to Release)
cmake -B build -G Ninja

# Build
cmake --build build

# The build produces:
#   build/Modules/SleepMask/sleepmask.dll   (sleep mask plugin)
#   build/Testing/controller.exe            (operator console)
#   build/Testing/beacon.exe                (headless beacon)
#   build/Testing/harness.exe               (plugin test harness)
```

For a Debug build with full diagnostic output:

```powershell
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Usage

### Sleep Mask Controller (v2.0.3)

```powershell
.\controller.exe ..\Modules\SleepMask\sleepmask.dll .\beacon.exe
```

Spawns a headless beacon process that loads the sleep mask DLL. The beacon auto-targets its own PE image for encryption. Commands at the `mask>` prompt:

```
info              — show technique and target
set ekko          — switch to Ekko (timer-queue ROP chain)
set kraken        — switch to KrakenMask (APC trampoline)
test <ms>         — one-shot self-test (allocate, encrypt, sleep, decrypt, verify)
run <ms>          — start callback loop (sleep encrypted → wake → poll → execute → repeat)
echo <msg>        — round-trip test
exit              — terminate beacon
```

In callback loop mode (`run 10000`), type commands while the beacon sleeps — they queue up and execute on the next wake cycle. Use Process Hacker to inspect the beacon's memory during the encrypted sleep window.

### Plugin Harness

```powershell
.\harness.exe
```

Interactive menu for runtime plugin management:

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
│   ├── Win32.h                        WinApiTable abstraction
│   ├── ReflectiveLoaderEngine.h       PE mapper + export resolver + FreeImage
│   ├── StompedLoaderEngine.h          Module stomping engine
│   └── PluginManager.h               Multi-plugin lifecycle manager
├── Modules/
│   ├── CmdPlugin/                     Command execution plugin
│   ├── EchoPlugin/                    Echo plugin (multi-plugin demo)
│   ├── CounterPlugin/                 Stateful counter (persistence demo)
│   └── SleepMask/
│       ├── sleepmask.cpp             Unified sleep mask (Ekko + KrakenMask)
│       └── CMakeLists.txt
├── Examples/
│   ├── basic_load.cpp                 Minimal single-plugin load + execute
│   ├── multi_plugin.cpp               Multiple plugins with lifecycle
│   ├── hot_reload.cpp                 Hot-reload with CounterPlugin
│   ├── custom_api_table.cpp           Custom WinApiTable with logging wrappers
│   ├── module_stomping.cpp            Load via module stomping engine
│   └── Makefile                      NMAKE build for standalone examples
├── Testing/
│   ├── main.cpp                       Interactive + CLI plugin harness
│   ├── controller.cpp                 Operator console (spawns beacon, pipe IPC)
│   ├── beacon.cpp                     Headless beacon (loads sleep mask, callback loop)
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
    return { "myplugin", "2.0.3", "My plugin description" };
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
