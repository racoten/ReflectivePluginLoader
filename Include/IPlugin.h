#pragma once
#include <Windows.h>
#include "Win32.h"

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
    const WinApiTable* Api;
} TaskApi;

struct PluginInfo {
    const char* name;
    const char* version;
    const char* description;
};

class IPlugin {
public:
    virtual void init()                  const = 0;
    virtual void execute(TaskApi* task)  const = 0;
    virtual void cleanup()               const = 0;
    virtual ~IPlugin() = default;
};
