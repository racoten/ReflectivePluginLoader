#include <Windows.h>
#include <new>
#include "../../Include/IPlugin.h"

class EchoPlugin : public IPlugin {
    const WinApiTable* m_api;
public:
    explicit EchoPlugin(const WinApiTable* api) : m_api(api) {}
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
static const WinApiTable* g_api = nullptr;

extern "C" IPlugin* __stdcall create_plugin(const WinApiTable* api) {
    if (g_plugin) return g_plugin;
    g_api = api;
    HANDLE heap = api ? api->GetProcessHeap() : GetProcessHeap();
    auto alloc  = api ? api->HeapAlloc : ::HeapAlloc;
    void* mem = alloc(heap, HEAP_ZERO_MEMORY, sizeof(EchoPlugin));
    if (!mem) return nullptr;
    g_plugin = ::new (mem) EchoPlugin(api);
    return g_plugin;
}

extern "C" void __stdcall destroy_plugin(IPlugin* p) {
    if (!p) return;
    p->~IPlugin();
    HANDLE heap = g_api ? g_api->GetProcessHeap() : GetProcessHeap();
    auto free_fn = g_api ? g_api->HeapFree : ::HeapFree;
    free_fn(heap, 0, p);
    if (p == g_plugin) g_plugin = nullptr;
}

extern "C" void __stdcall plugin_init(IPlugin* p) {
    if (!p) p = create_plugin(g_api);
    if (p) p->init();
}

extern "C" void __stdcall plugin_exec(TaskApi* task) {
    if (!g_plugin) g_plugin = create_plugin(task->Api);
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
    return { "echo", "2.0.2", "Echoes task command to stdout" };
}
