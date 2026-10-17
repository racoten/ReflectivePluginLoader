// multi_plugin.cpp — Load multiple plugins, list them, execute all, unload.
//
// Usage:
//   multi_plugin.exe <cmd.dll> <echo.dll> <counter.dll>

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

static bool LoadFromFile(PluginManager& pm, const char* id, const char* path) {
    auto dll = ReadFile(path);
    if (dll.empty()) {
        printf("[-] Cannot read %s\n", path);
        return false;
    }
    bool ok = pm.LoadPlugin(id, dll.data(), dll.size(), LoaderEngine::Reflective);
    memset(dll.data(), 0, dll.size());
    return ok;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <cmd.dll> <echo.dll> <counter.dll>\n", argv[0]);
        return 1;
    }

    PluginManager pm;

    // Load three plugins concurrently tracked by the manager
    LoadFromFile(pm, "cmd",     argv[1]);
    LoadFromFile(pm, "echo",    argv[2]);
    LoadFromFile(pm, "counter", argv[3]);

    printf("[+] Loaded %zu plugins\n", pm.GetPluginCount());

    // List all plugins with their metadata
    auto ids = pm.GetPluginIds();
    for (auto& id : ids) {
        std::string name, version;
        LoaderEngine engine;
        pm.GetPluginInfo(id, name, version, engine);
        printf("  [%s] name=%s ver=%s engine=%s\n",
               id.c_str(), name.c_str(), version.c_str(),
               engine == LoaderEngine::Stomped ? "stomped" : "reflective");
    }

    // Execute all plugins with the same command
    TaskApi task{};
    task.TaskId = "batch";        task.TaskIdLen = 5;
    task.Instruction = "exec";    task.InstructionLen = 4;
    task.Command = "whoami";      task.CommandLen = 6;

    printf("\n--- Execute all ---\n");
    pm.ExecuteAll(&task);

    // Unload one, verify count, then unload the rest
    pm.UnloadPlugin("echo");
    printf("\n[+] After unloading 'echo': %zu plugins remain\n", pm.GetPluginCount());

    pm.UnloadAll();
    printf("[+] All plugins unloaded\n");

    return 0;
}
