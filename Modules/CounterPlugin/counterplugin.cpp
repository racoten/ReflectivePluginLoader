#include <Windows.h>
#include <new>
#include "../../Include/IPlugin.h"

class CounterPlugin : public IPlugin {
    mutable int m_count;
public:
    explicit CounterPlugin(const WinApiTable*) : m_count(0) {}

    void init()    const override { m_count = 0; }
    void cleanup() const override {}
    void execute(TaskApi* task) const override {
        ++m_count;

        char buf[128];
        int len = wsprintfA(buf, "[counter] execution #%d", m_count);

        if (task->Command && task->CommandLen > 0) {
            buf[len++] = ' '; buf[len++] = '-'; buf[len++] = ' ';
            DWORD maxCmd = (DWORD)(sizeof(buf) - len - 2);
            DWORD cmdLen = (task->CommandLen < maxCmd) ? task->CommandLen : maxCmd;
            CopyMemory(buf + len, task->Command, cmdLen);
            len += cmdLen;
        }

        buf[len++] = '\n';

        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut && hOut != INVALID_HANDLE_VALUE) {
            DWORD wrote = 0;
            WriteFile(hOut, buf, len, &wrote, nullptr);
        }
    }
};

static IPlugin* g_plugin = nullptr;
static const WinApiTable* g_api = nullptr;

extern "C" IPlugin* __stdcall create_plugin(const WinApiTable* api) {
    if (g_plugin) return g_plugin;
    g_api = api;
    HANDLE heap = api ? api->GetProcessHeap() : GetProcessHeap();
    auto alloc  = api ? api->HeapAlloc : ::HeapAlloc;
    void* mem = alloc(heap, HEAP_ZERO_MEMORY, sizeof(CounterPlugin));
    if (!mem) return nullptr;
    g_plugin = ::new (mem) CounterPlugin(api);
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

PLUGIN_EXPORT PluginInfo PLUGIN_CALL plugin_info() {
    return { "counter", "2.0.3", "Stateful execution counter" };
}
