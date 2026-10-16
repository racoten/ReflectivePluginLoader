#include <Windows.h>
#include <new>
#include "../../Include/IPlugin.h"

class EchoPlugin : public IPlugin {
public:
    void init()    const override {}
    void cleanup() const override {}
    void execute(TaskApi* task) const override {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!hOut || hOut == INVALID_HANDLE_VALUE) return;

        const char prefix[] = "[echo] ";
        DWORD wrote = 0;
        WriteFile(hOut, prefix, sizeof(prefix) - 1, &wrote, nullptr);

        if (task->Command && task->CommandLen > 0)
            WriteFile(hOut, task->Command, task->CommandLen, &wrote, nullptr);
        else {
            const char none[] = "(no command)";
            WriteFile(hOut, none, sizeof(none) - 1, &wrote, nullptr);
        }

        WriteFile(hOut, "\n", 1, &wrote, nullptr);
    }
};

static IPlugin* g_plugin = nullptr;

extern "C" IPlugin* __stdcall create_plugin() {
    if (g_plugin) return g_plugin;
    void* mem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(EchoPlugin));
    if (!mem) return nullptr;
    g_plugin = ::new (mem) EchoPlugin();
    return g_plugin;
}

extern "C" void __stdcall destroy_plugin(IPlugin* p) {
    if (!p) return;
    p->~IPlugin();
    HeapFree(GetProcessHeap(), 0, p);
    if (p == g_plugin) g_plugin = nullptr;
}

extern "C" void __stdcall plugin_init(IPlugin* p) {
    if (!p) p = create_plugin();
    if (p) p->init();
}

extern "C" void __stdcall plugin_exec(TaskApi* task) {
    if (!g_plugin) g_plugin = create_plugin();
    if (g_plugin) g_plugin->execute(task);
}

extern "C" void __stdcall plugin_cleanup(IPlugin* p) {
    if (!p) p = g_plugin;
    if (p) p->cleanup();
}

struct PluginInfo {
    const char* name;
    const char* version;
    const char* description;
};

extern "C" __declspec(dllexport) PluginInfo __stdcall plugin_info() {
    return { "echo", "2.0.1", "Echoes task command to stdout" };
}
