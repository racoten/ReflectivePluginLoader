// custom_api_table.cpp — Swap in a custom WinApiTable with logging wrappers.
//
// This demonstrates the KunaiGate/SealApi integration point: replace raw
// Win32 calls with custom function pointers that log, redirect, or wrap
// every API call the loader and plugins make.
//
// In production, you'd point these at SealApi/KunaiGate wrappers for
// syscall dispatch, callstack spoofing, and parameter sanitization.
//
// Usage:
//   custom_api_table.exe <plugin.dll> <command>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include "../Include/PluginManager.h"

static std::vector<uint8_t> ReadFile(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(sz);
    f.read((char*)buf.data(), sz);
    return buf;
}

// --- Logging wrappers around the real Win32 APIs ---
// Each wrapper calls the real API and logs the call. In a real evasion
// scenario, these would be KunaiGate entry points that perform indirect
// syscalls, spoof the call stack, or sanitize parameters.

static LPVOID WINAPI LoggingVirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD prot) {
    LPVOID result = ::VirtualAlloc(addr, size, type, prot);
    fprintf(stderr, "[API] VirtualAlloc(addr=%p, size=0x%llx, prot=0x%lx) -> %p\n",
            addr, (unsigned long long)size, prot, result);
    return result;
}

static BOOL WINAPI LoggingVirtualFree(LPVOID addr, SIZE_T size, DWORD type) {
    fprintf(stderr, "[API] VirtualFree(addr=%p)\n", addr);
    return ::VirtualFree(addr, size, type);
}

static BOOL WINAPI LoggingVirtualProtect(LPVOID addr, SIZE_T size, DWORD newProt, PDWORD oldProt) {
    BOOL result = ::VirtualProtect(addr, size, newProt, oldProt);
    fprintf(stderr, "[API] VirtualProtect(addr=%p, size=0x%llx, prot=0x%lx)\n",
            addr, (unsigned long long)size, newProt);
    return result;
}

static HMODULE WINAPI LoggingLoadLibraryA(LPCSTR name) {
    HMODULE result = ::LoadLibraryA(name);
    fprintf(stderr, "[API] LoadLibraryA(\"%s\") -> %p\n", name, (void*)result);
    return result;
}

static FARPROC WINAPI LoggingGetProcAddress(HMODULE mod, LPCSTR name) {
    FARPROC result = ::GetProcAddress(mod, name);
    if ((uintptr_t)name > 0xFFFF)
        fprintf(stderr, "[API] GetProcAddress(%p, \"%s\") -> %p\n", (void*)mod, name, (void*)result);
    else
        fprintf(stderr, "[API] GetProcAddress(%p, ord=%llu) -> %p\n",
                (void*)mod, (unsigned long long)(uintptr_t)name, (void*)result);
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <plugin.dll> <command>\n", argv[0]);
        return 1;
    }

    auto dll = ReadFile(argv[1]);
    if (dll.empty()) {
        printf("[-] Cannot read %s\n", argv[1]);
        return 1;
    }

    // Build a custom WinApiTable with logging wrappers
    WinApiTable loggingApi = DefaultWinApiTable();
    loggingApi.VirtualAlloc   = LoggingVirtualAlloc;
    loggingApi.VirtualFree    = LoggingVirtualFree;
    loggingApi.VirtualProtect = LoggingVirtualProtect;
    loggingApi.LoadLibraryA   = LoggingLoadLibraryA;
    loggingApi.GetProcAddress = LoggingGetProcAddress;

    PluginManager pm;
    pm.SetWinApiTable(loggingApi);

    printf("[+] Using custom API table (logging mode)\n\n");

    pm.LoadPlugin("test", dll.data(), dll.size(), LoaderEngine::Reflective);
    memset(dll.data(), 0, dll.size());

    TaskApi task{};
    task.TaskId = "api-test";     task.TaskIdLen = 8;
    task.Instruction = "exec";    task.InstructionLen = 4;
    task.Command = argv[2];       task.CommandLen = (DWORD)strlen(argv[2]);

    printf("\n--- Execute ---\n");
    pm.ExecutePlugin("test", &task);

    printf("\n--- Unload ---\n");
    pm.UnloadAll();

    return 0;
}
