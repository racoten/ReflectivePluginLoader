#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <Windows.h>
#include "../Include/PluginManager.h"

#ifdef NDEBUG
#define DBG(...) ((void)0)
#else
#define DBG(fmt, ...) do { fprintf(stderr, "[DBG] " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while(0)

static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep) {
    fprintf(stderr, "\n[CRASH] code=0x%08lX addr=%p RIP=0x%llX RSP=0x%llX\n",
            ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress,
            ep->ContextRecord->Rip, ep->ContextRecord->Rsp);
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

static std::vector<uint8_t> ReadFileBytes(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(sz);
    f.read((char*)buf.data(), sz);
    return buf;
}

static void PrintScanCommands(DWORD pid) {
    printf("\n========================================================\n");
    printf("  PID: %lu\n", pid);
    printf("  pe-sieve64.exe /pid %lu /data 3 /iat 2\n", pid);
    printf("  moneta64.exe -p %lu -m ioc\n", pid);
    printf("========================================================\n");
    fflush(stdout);
}

static void ListPlugins(PluginManager& pm) {
    auto ids = pm.GetPluginIds();
    printf("\n--- Loaded plugins: %zu ---\n", ids.size());
    for (auto& id : ids) {
        std::string name, version;
        LoaderEngine engine;
        if (pm.GetPluginInfo(id, name, version, engine)) {
            printf("  [%s] name=%s ver=%s engine=%s\n",
                   id.c_str(), name.c_str(), version.c_str(),
                   engine == LoaderEngine::Stomped ? "stomped" : "reflective");
        }
    }
    printf("---\n");
    fflush(stdout);
}

static void PrintMenu() {
    printf("\n=== ReflectivePluginLoader v2.1 ===\n");
    printf("[1] Load plugin\n");
    printf("[2] Unload plugin\n");
    printf("[3] Execute plugin\n");
    printf("[4] Reload plugin\n");
    printf("[5] List plugins\n");
    printf("[6] Execute all\n");
    printf("[7] Scan commands\n");
    printf("[q] Quit\n");
    printf("> ");
    fflush(stdout);
}

static void ReadLine(char* buf, int maxLen) {
    if (!fgets(buf, maxLen, stdin)) buf[0] = '\0';
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
}

static void InteractiveMode(PluginManager& pm) {
    char line[512], id[128], path[MAX_PATH], cmd[256], sac[MAX_PATH];

    for (;;) {
        PrintMenu();
        ReadLine(line, sizeof(line));
        if (line[0] == 'q' || line[0] == 'Q') break;

        switch (line[0]) {
        case '1': {
            printf("Plugin ID: "); fflush(stdout);
            ReadLine(id, sizeof(id));
            printf("DLL path: "); fflush(stdout);
            ReadLine(path, sizeof(path));
            printf("Engine [r]eflective / [s]tomped: "); fflush(stdout);
            ReadLine(line, sizeof(line));
            LoaderEngine eng = (line[0] == 's' || line[0] == 'S')
                             ? LoaderEngine::Stomped : LoaderEngine::Reflective;
            const char* sacPtr = nullptr;
            if (eng == LoaderEngine::Stomped) {
                printf("Sacrificial DLL: "); fflush(stdout);
                ReadLine(sac, sizeof(sac));
                sacPtr = sac;
            }
            auto bytes = ReadFileBytes(path);
            if (bytes.empty()) {
                printf("[-] Failed to read: %s\n", path);
                break;
            }
            if (pm.LoadPlugin(id, bytes.data(), bytes.size(), eng, sacPtr))
                printf("[+] Loaded '%s'\n", id);
            else
                printf("[-] Failed to load '%s'\n", id);
            memset(bytes.data(), 0, bytes.size());
            break;
        }
        case '2':
            printf("Plugin ID: "); fflush(stdout);
            ReadLine(id, sizeof(id));
            if (pm.UnloadPlugin(id))
                printf("[+] Unloaded '%s'\n", id);
            else
                printf("[-] Plugin '%s' not found\n", id);
            break;
        case '3':
            printf("Plugin ID: "); fflush(stdout);
            ReadLine(id, sizeof(id));
            printf("Command: "); fflush(stdout);
            ReadLine(cmd, sizeof(cmd));
            {
                TaskApi task{};
                task.TaskId = "interactive"; task.TaskIdLen = 11;
                task.Instruction = "exec"; task.InstructionLen = 4;
                task.Command = cmd; task.CommandLen = (DWORD)strlen(cmd);
                if (!pm.ExecutePlugin(id, &task))
                    printf("[-] Failed to execute '%s'\n", id);
            }
            break;
        case '4':
            printf("Plugin ID: "); fflush(stdout);
            ReadLine(id, sizeof(id));
            printf("New DLL path: "); fflush(stdout);
            ReadLine(path, sizeof(path));
            {
                auto bytes = ReadFileBytes(path);
                if (bytes.empty()) {
                    printf("[-] Failed to read: %s\n", path);
                    break;
                }
                if (pm.ReloadPlugin(id, bytes.data(), bytes.size()))
                    printf("[+] Reloaded '%s'\n", id);
                else
                    printf("[-] Failed to reload '%s'\n", id);
                memset(bytes.data(), 0, bytes.size());
            }
            break;
        case '5':
            ListPlugins(pm);
            break;
        case '6':
            printf("Command for all: "); fflush(stdout);
            ReadLine(cmd, sizeof(cmd));
            {
                TaskApi task{};
                task.TaskId = "batch"; task.TaskIdLen = 5;
                task.Instruction = "exec"; task.InstructionLen = 4;
                task.Command = cmd; task.CommandLen = (DWORD)strlen(cmd);
                pm.ExecuteAll(&task);
            }
            break;
        case '7':
            PrintScanCommands(GetCurrentProcessId());
            break;
        default:
            printf("Unknown option: %c\n", line[0]);
        }
    }
}

// ---------------------------------------------------------------------------
// CLI-arg mode: --load <id> <path> [--stomp <sac>]
//               --exec <id> <cmd>
//               --reload <id> <path>
//               --unload <id>
//               --list
//               --unload-all
// ---------------------------------------------------------------------------
static bool CliMode(int argc, char* argv[], PluginManager& pm) {
    bool handled = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--load") == 0 && i + 2 < argc) {
            handled = true;
            const char* id   = argv[++i];
            const char* path = argv[++i];
            LoaderEngine eng = LoaderEngine::Reflective;
            const char* sac  = nullptr;
            if (i + 2 < argc && strcmp(argv[i + 1], "--stomp") == 0) {
                eng = LoaderEngine::Stomped;
                sac = argv[i + 2];
                i += 2;
            }
            auto bytes = ReadFileBytes(path);
            if (bytes.empty()) { fprintf(stderr, "[-] Cannot read %s\n", path); continue; }
            if (pm.LoadPlugin(id, bytes.data(), bytes.size(), eng, sac))
                printf("[+] Loaded '%s'\n", id);
            else
                fprintf(stderr, "[-] Failed to load '%s'\n", id);
            memset(bytes.data(), 0, bytes.size());
        }
        else if (strcmp(argv[i], "--exec") == 0 && i + 2 < argc) {
            handled = true;
            const char* id  = argv[++i];
            const char* cmd = argv[++i];
            TaskApi task{};
            task.TaskId = "cli"; task.TaskIdLen = 3;
            task.Instruction = "exec"; task.InstructionLen = 4;
            task.Command = cmd; task.CommandLen = (DWORD)strlen(cmd);
            if (!pm.ExecutePlugin(id, &task))
                fprintf(stderr, "[-] Cannot execute '%s'\n", id);
        }
        else if (strcmp(argv[i], "--reload") == 0 && i + 2 < argc) {
            handled = true;
            const char* id   = argv[++i];
            const char* path = argv[++i];
            auto bytes = ReadFileBytes(path);
            if (bytes.empty()) { fprintf(stderr, "[-] Cannot read %s\n", path); continue; }
            if (pm.ReloadPlugin(id, bytes.data(), bytes.size()))
                printf("[+] Reloaded '%s'\n", id);
            else
                fprintf(stderr, "[-] Failed to reload '%s'\n", id);
            memset(bytes.data(), 0, bytes.size());
        }
        else if (strcmp(argv[i], "--unload") == 0 && i + 1 < argc) {
            handled = true;
            pm.UnloadPlugin(argv[++i]);
        }
        else if (strcmp(argv[i], "--list") == 0) {
            handled = true;
            ListPlugins(pm);
        }
        else if (strcmp(argv[i], "--unload-all") == 0) {
            handled = true;
            pm.UnloadAll();
        }
    }
    return handled;
}

int main(int argc, char* argv[]) {
#ifndef NDEBUG
    SetUnhandledExceptionFilter(CrashHandler);
#endif

    PluginManager pm;

    if (argc > 1 && argv[1][0] == '-') {
        CliMode(argc, argv, pm);
    } else if (argc > 1) {
        printf("Usage: %s [interactive | CLI args]\n", argv[0]);
        printf("  Interactive: %s\n", argv[0]);
        printf("  CLI: %s --load <id> <dll> [--stomp <sac>] --exec <id> <cmd> ...\n", argv[0]);
        return 1;
    } else {
        InteractiveMode(pm);
    }

    pm.UnloadAll();
    return 0;
}
