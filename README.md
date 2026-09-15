# ReflectivePluginLoader

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A minimal reflective PE mapper with a hot-swappable plugin interface for Windows x64. Maps a DLL straight from a byte buffer in memory, resolves its exports, and calls into a clean `IPlugin` ABI without touching `LoadLibrary`. Companion code for the blog post on reflective loaders and modular plugin architectures.

## Blog Post

<!-- TODO: Replace with your published URL -->
> See the full writeup: [Using Reflective Loaders to Replace LoadLibrary for Hot-Swappable Modules in C++](#)

## Quick Start

Requires Visual Studio 2019+ with C++ desktop workload, or any MSVC toolchain with CMake 3.15+.

```powershell
# Configure
cmake -B build -G "Visual Studio 17 2022" -A x64

# Build
cmake --build build --config Release

# The build produces:
#   build/Release/cmdplugin.dll   (example plugin)
#   build/Release/harness.exe     (test harness)
```

## Usage

```powershell
# Map cmdplugin.dll from disk, run "dir C:\"
harness.exe cmdplugin.dll "dir C:\"

# Default: loads cmdplugin.dll, runs "whoami"
harness.exe
```

The harness reads the DLL into a byte buffer, maps it with the reflective loader, resolves the plugin exports, and dispatches the command through the `IPlugin` interface.

## Project Structure

```
ReflectivePluginLoader/
├── CMakeLists.txt              # Root build
├── Include/
│   ├── IPlugin.h               # Plugin ABI (TaskApi, IPlugin, helpers)
│   └── ReflectiveLoaderEngine.h # PE mapper + export resolver
├── Modules/
│   └── CmdPlugin/
│       ├── cmdplugin.cpp        # Example: command execution plugin
│       └── CMakeLists.txt
├── Testing/
│   ├── main.cpp                 # Test harness (loads DLL from file)
│   └── CMakeLists.txt
└── Tools/
    └── file2hex.py              # Convert a DLL to a C byte array
```

## Writing Your Own Module

1. Create a new directory under `Modules/`.
2. Include `IPlugin.h` and implement the `IPlugin` interface:

```cpp
#include "IPlugin.h"

class MyPlugin : public IPlugin {
public:
    void init() const override { /* setup */ }
    void execute(TaskApi* task) const override { /* do work */ }
    void cleanup() const override { /* teardown */ }
};
```

3. Implement the five exported functions (`create_plugin`, `destroy_plugin`, `plugin_init`, `plugin_exec`, `plugin_cleanup`) using `HeapAlloc`/placement `new` for CRT-safe cross-module allocation.

4. Add a `CMakeLists.txt` and register it in the root `CMakeLists.txt` with `add_subdirectory()`.

The host doesn't need to know what your module does internally. It maps, resolves, calls `init -> execute -> cleanup`, and moves on.

## Known Limitations

The mapper handles the basics and deliberately stops there:

- **Supported:** Base relocations, import resolution, per-section memory protections
- **Not supported:** TLS callbacks, delay-load imports, forwarded exports, CFG metadata, SEH table registration

If a module needs any of those, either extend the mapper or reject the module early with a clear error. Silent half-support is the worst failure mode.

## References

- [stephenfewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) - The original reflective loader
- [ired.team - Reflective DLL Injection](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection) - Walkthrough and PoC
- [fancycode/MemoryModule](https://github.com/fancycode/MemoryModule) - Full-featured "load DLL from memory" library
- [PE Format (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) - PE/COFF specification

## License

[MIT](LICENSE)
