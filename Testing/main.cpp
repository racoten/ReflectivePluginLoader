#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>
#include <conio.h>
#include <Windows.h>
#include "../Include/IPlugin.h"
#include "../Include/ReflectiveLoaderEngine.h"
#include "../Include/StompedLoaderEngine.h"

using CreatePlugin_t  = IPlugin* (__stdcall*)();
using DestroyPlugin_t = void(__stdcall*)(IPlugin*);
using PluginInit_t    = void(__stdcall*)(IPlugin*);
using PluginExec_t    = void(__stdcall*)(const TaskApi*);
using PluginCleanup_t = void(__stdcall*)(IPlugin*);

#ifdef NDEBUG
#define DBG(...) ((void)0)
#else
#define DBG(fmt, ...) do { fprintf(stderr, "[DBG] " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while(0)

static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep) {
    fprintf(stderr, "\n[CRASH] code=0x%08lX addr=%p RIP=0x%llX RSP=0x%llX\n",
            ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress,
            ep->ContextRecord->Rip, ep->ContextRecord->Rsp);
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

static std::vector<uint8_t> ReadFileBytes(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(sz);
    f.read((char*)buf.data(), sz);
    return buf;
}

static void PrintScanCommands(DWORD pid, const char* label) {
    printf("\n========================================================\n");
    printf("  %s\n", label);
    printf("  PID: %lu\n", pid);
    printf("  ------------------------------------------------------\n");
    printf("  pe-sieve64.exe /pid %lu /data 3 /iat 2\n", pid);
    printf("  moneta64.exe -p %lu -m ioc\n", pid);
    printf("  hollows_hunter64.exe /pid %lu /data 3\n", pid);
    printf("========================================================\n");
    fflush(stdout);
}

// SEH wrapper -- no C++ objects allowed in __try (MSVC C2712).
static void CallPluginSEH(CreatePlugin_t create, DestroyPlugin_t destroy,
                           PluginInit_t init, PluginExec_t exec,
                           PluginCleanup_t cleanup, const char* cmd) {
    __try {
        IPlugin* plugin = create();
        if (!plugin) { fprintf(stderr, "[-] create_plugin returned null\n"); return; }
        init(plugin);

        TaskApi task{};
        task.TaskId = "test"; task.TaskIdLen = 4;
        task.Instruction = "exec"; task.InstructionLen = 4;
        task.Command = cmd; task.CommandLen = (cmd ? (DWORD)lstrlenA(cmd) : 0);

        exec(&task);
        cleanup(plugin);
        destroy(plugin);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[-] SEH exception 0x%08lX during plugin execution\n",
                GetExceptionCode());
    }
}

// ---- Classic reflective load ----

static void TestReflective(const uint8_t* dll, size_t size, const char* cmd) {
    MemModule mod = MapImage(dll, size);
    if (!mod.base) { fprintf(stderr, "[-] MapImage failed\n"); return; }

    auto create  = (CreatePlugin_t)GetExport(mod, "create_plugin");
    auto destroy = (DestroyPlugin_t)GetExport(mod, "destroy_plugin");
    auto init    = (PluginInit_t)GetExport(mod, "plugin_init");
    auto exec    = (PluginExec_t)GetExport(mod, "plugin_exec");
    auto cleanup = (PluginCleanup_t)GetExport(mod, "plugin_cleanup");

    if (!create || !destroy || !init || !exec || !cleanup) {
        fprintf(stderr, "[-] Missing exports\n"); return;
    }

    DBG("Reflective base=%p", mod.base);

    CallPluginSEH(create, destroy, init, exec, cleanup, cmd);

    DWORD pid = GetCurrentProcessId();
    PrintScanCommands(pid, "POST-EXECUTION (reflective)");
    printf("  Press any key to exit...\n"); fflush(stdout);
    _getch();
}

// ---- Module stomping ----

static void TestStomped(uint8_t* dll, size_t size, const char* cmd,
                        const char* sacrificial) {
    StompedModule mod = StompModule(dll, size, sacrificial);
    if (!mod.stompedBase) {
        fprintf(stderr, "[-] StompModule failed\n");
        return;
    }

    auto create  = (CreatePlugin_t)GetStompedExport(mod, "create_plugin");
    auto destroy = (DestroyPlugin_t)GetStompedExport(mod, "destroy_plugin");
    auto init    = (PluginInit_t)GetStompedExport(mod, "plugin_init");
    auto exec    = (PluginExec_t)GetStompedExport(mod, "plugin_exec");
    auto cleanup = (PluginCleanup_t)GetStompedExport(mod, "plugin_cleanup");

    if (!create || !destroy || !init || !exec || !cleanup) {
        fprintf(stderr, "[-] Missing exports after stomping\n");
        FreeStompedModule(mod);
        return;
    }

    FreePrivateMapping(mod);
    DBG("Stomped base=%p, exports resolved, private mapping freed", mod.stompedBase);

    CallPluginSEH(create, destroy, init, exec, cleanup, cmd);

    FreeStompedModule(mod);

    // Scrub raw DLL bytes from heap before the scan window.
    memset(dll, 0, size);

    DWORD pid = GetCurrentProcessId();
    PrintScanCommands(pid, "POST-CLEANUP (module stomping)");
    printf("  Press any key to exit...\n"); fflush(stdout);
    _getch();
}

// ---- Entry point ----

static void PrintUsage(const char* exe) {
    printf("Usage: %s <plugin.dll> [command] [--stomp <sacrificial.dll>]\n\n", exe);
    printf("Modes:\n");
    printf("  (default)    Reflective load into private memory\n");
    printf("  --stomp      Module stomping via a legitimately loaded DLL\n\n");
    printf("Examples:\n");
    printf("  %s cmdplugin.dll whoami\n", exe);
    printf("  %s cmdplugin.dll whoami --stomp xpsservices.dll\n", exe);
}

int main(int argc, char* argv[]) {
#ifndef NDEBUG
    SetUnhandledExceptionFilter(CrashHandler);
#endif

    if (argc < 2) { PrintUsage(argv[0]); return 1; }

    const char* dllPath    = argv[1];
    const char* cmd        = "whoami";
    const char* sacrificial = nullptr;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--stomp") == 0 && i + 1 < argc)
            sacrificial = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
            { PrintUsage(argv[0]); return 0; }
        else
            cmd = argv[i];
    }

    auto bytes = ReadFileBytes(dllPath);
    if (bytes.empty()) {
        fprintf(stderr, "[-] Failed to read: %s\n", dllPath);
        return 1;
    }

    if (sacrificial)
        TestStomped(bytes.data(), bytes.size(), cmd, sacrificial);
    else
        TestReflective(bytes.data(), bytes.size(), cmd);

    // Final scrub of any remaining DLL bytes on the heap.
    memset(bytes.data(), 0, bytes.size());
    std::vector<uint8_t>().swap(bytes);

    return 0;
}
