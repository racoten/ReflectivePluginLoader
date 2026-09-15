#pragma once
#include <Windows.h>

#ifndef PLUGIN_CALL
#define PLUGIN_CALL __stdcall
#endif

#ifndef PLUGIN_EXPORT
#define PLUGIN_EXPORT extern "C" __declspec(dllexport)
#endif

typedef struct TaskApi {
    const char* TaskId;        DWORD TaskIdLen;
    const char* Instruction;   DWORD InstructionLen;
    const char* Command;       DWORD CommandLen;
    const char* Arguments;     DWORD ArgumentsLen;
    const char* File;          DWORD FileLen;
    const char* ExecTime;      DWORD ExecTimeLen;
} TaskApi;

class IPlugin {
public:
    virtual void init()   const = 0;
    virtual void execute(TaskApi* task) const = 0;
    virtual void cleanup() const = 0;
    virtual ~IPlugin() = default;
};

static inline DWORD CStrLenA(const char* s) {
    return s ? (DWORD)lstrlenA(s) : 0;
}

static void BeaconCout(const char* s, DWORD len = 0) {
    if (!s) return;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!hOut || hOut == INVALID_HANDLE_VALUE) return;
    if (len == 0) len = (DWORD)lstrlenA(s);
    DWORD n = 0;
    WriteFile(hOut, s, len, &n, nullptr);
}

static void BeaconPipeOutput(HANDLE hRead) {
    BYTE buf[4096];
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(hRead, buf, sizeof(buf), &got, nullptr) || got == 0) break;
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut && hOut != INVALID_HANDLE_VALUE) {
            DWORD wrote = 0;
            WriteFile(hOut, buf, got, &wrote, nullptr);
        }
    }
}

static inline void* PluginAlloc(SIZE_T sz, BOOL zero = TRUE) {
    return HeapAlloc(GetProcessHeap(), zero ? HEAP_ZERO_MEMORY : 0, sz);
}
static inline void  PluginFree(void* p) {
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

PLUGIN_EXPORT IPlugin* PLUGIN_CALL create_plugin();
PLUGIN_EXPORT void     PLUGIN_CALL destroy_plugin(IPlugin*);

PLUGIN_EXPORT void     PLUGIN_CALL plugin_init(IPlugin*);
PLUGIN_EXPORT void     PLUGIN_CALL plugin_exec(TaskApi* task);
PLUGIN_EXPORT void     PLUGIN_CALL plugin_cleanup(IPlugin*);
