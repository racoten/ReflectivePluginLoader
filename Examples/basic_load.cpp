// basic_load.cpp — Minimal example: load one plugin, execute it, unload.
//
// Build (not part of CMake — standalone reference):
//   cl /EHsc /std:c++17 /I ../Include basic_load.cpp /link /out:basic_load.exe
//
// Usage:
//   basic_load.exe <plugin.dll> <command>

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
    if (argc < 3) {
        printf("Usage: %s <plugin.dll> <command>\n", argv[0]);
        return 1;
    }

    auto dll = ReadFile(argv[1]);
    if (dll.empty()) {
        printf("[-] Cannot read %s\n", argv[1]);
        return 1;
    }

    PluginManager pm;

    // Load the plugin with the reflective engine
    if (!pm.LoadPlugin("myplugin", dll.data(), dll.size(), LoaderEngine::Reflective)) {
        printf("[-] Failed to load plugin\n");
        return 1;
    }
    printf("[+] Plugin loaded\n");

    // Scrub the raw DLL bytes from memory
    memset(dll.data(), 0, dll.size());
    dll.clear();

    // Build a task and execute
    TaskApi task{};
    task.TaskId = "example";      task.TaskIdLen = 7;
    task.Instruction = "exec";    task.InstructionLen = 4;
    task.Command = argv[2];       task.CommandLen = (DWORD)strlen(argv[2]);

    pm.ExecutePlugin("myplugin", &task);

    // Unload — tears down plugin instance, frees mapped image and imports
    pm.UnloadPlugin("myplugin");
    printf("[+] Plugin unloaded\n");

    return 0;
}
