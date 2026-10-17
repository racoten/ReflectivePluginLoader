// hot_reload.cpp — Demonstrate hot-reload: swap a plugin DLL at runtime.
//
// The CounterPlugin keeps an internal counter that increments on each
// execute(). After a reload, the counter resets to 0 — proving the old
// instance was torn down and a fresh one was created.
//
// Usage:
//   hot_reload.exe <counterplugin.dll>

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
    if (argc < 2) {
        printf("Usage: %s <counterplugin.dll>\n", argv[0]);
        return 1;
    }

    auto dll = ReadFile(argv[1]);
    if (dll.empty()) {
        printf("[-] Cannot read %s\n", argv[1]);
        return 1;
    }

    PluginManager pm;
    pm.LoadPlugin("counter", dll.data(), dll.size(), LoaderEngine::Reflective);

    TaskApi task{};
    task.TaskId = "reload-test";  task.TaskIdLen = 11;
    task.Instruction = "exec";    task.InstructionLen = 4;

    // Execute three times — counter should print 1, 2, 3
    printf("--- Before reload ---\n");
    for (int i = 0; i < 3; i++) {
        char cmd[32];
        int len = sprintf(cmd, "call-%d", i + 1);
        task.Command = cmd;
        task.CommandLen = (DWORD)len;
        pm.ExecutePlugin("counter", &task);
    }

    // Hot-reload with the same DLL (simulates swapping in an updated build)
    printf("\n--- Reloading ---\n");
    auto fresh = ReadFile(argv[1]);
    if (pm.ReloadPlugin("counter", fresh.data(), fresh.size()))
        printf("[+] Reloaded 'counter'\n");
    memset(fresh.data(), 0, fresh.size());

    // Execute again — counter resets, should print 1, 2
    printf("\n--- After reload ---\n");
    for (int i = 0; i < 2; i++) {
        char cmd[32];
        int len = sprintf(cmd, "post-reload-%d", i + 1);
        task.Command = cmd;
        task.CommandLen = (DWORD)len;
        pm.ExecutePlugin("counter", &task);
    }

    pm.UnloadAll();
    return 0;
}
