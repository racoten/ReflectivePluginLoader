#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>
#include "../Include/IPlugin.h"
#include "../Include/ReflectiveLoaderEngine.h"

using CreatePlugin_t = IPlugin* (__stdcall*)();
using DestroyPlugin_t = void(__stdcall*)(IPlugin*);
using PluginInit_t = void(__stdcall*)(IPlugin*);
using PluginExec_t = void(__stdcall*)(const TaskApi*);
using PluginCleanup_t = void(__stdcall*)(IPlugin*);

std::vector<uint8_t> ReadFileBytes(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(sz);
    f.read((char*)buf.data(), sz);
    return buf;
}

void Test_Extension_CMD(const uint8_t* dllBytes, size_t dllSize, const char* cmd) {
    MemModule mod = MapImage(dllBytes, dllSize);
    if (!mod.base) { std::cerr << "[-] map failed\n"; return; }

    auto create_plugin = (CreatePlugin_t)GetExport(mod, "create_plugin");
    auto destroy_plugin = (DestroyPlugin_t)GetExport(mod, "destroy_plugin");
    auto plugin_init = (PluginInit_t)GetExport(mod, "plugin_init");
    auto plugin_exec = (PluginExec_t)GetExport(mod, "plugin_exec");
    auto plugin_cleanup = (PluginCleanup_t)GetExport(mod, "plugin_cleanup");

    if (!create_plugin || !destroy_plugin || !plugin_init || !plugin_exec || !plugin_cleanup) {
        std::cerr << "[-] missing one or more exports\n"; return;
    }

    IPlugin* plugin = create_plugin();
    if (!plugin) { std::cerr << "[-] create_plugin returned null\n"; return; }

    plugin_init(plugin);

    TaskApi task{};
    task.TaskId = "local-test";   task.TaskIdLen = (DWORD)lstrlenA(task.TaskId);
    task.Instruction = "exec";    task.InstructionLen = (DWORD)lstrlenA(task.Instruction);
    task.Command = cmd;           task.CommandLen = (cmd ? (DWORD)lstrlenA(cmd) : 0);

    plugin_exec(&task);
    plugin_cleanup(plugin);
    destroy_plugin(plugin);
}

int main(int argc, char* argv[]) {
    const char* dllPath = argc > 1 ? argv[1] : "cmdplugin.dll";
    const char* cmd = argc > 2 ? argv[2] : "whoami";

    auto bytes = ReadFileBytes(dllPath);
    if (bytes.empty()) {
        std::cerr << "[-] failed to read: " << dllPath << "\n";
        return 1;
    }

    std::cout << "[+] loaded " << bytes.size() << " bytes from " << dllPath << "\n";
    Test_Extension_CMD(bytes.data(), bytes.size(), cmd);
    return 0;
}
