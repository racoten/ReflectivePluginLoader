// controller.cpp — Interactive operator console with beacon callback loop.
//
// Spawns beacon.exe, lets you configure the sleep mask (set technique,
// run one-shot tests), then start a callback loop with "run <interval_ms>".
//
// In the callback loop the beacon sleeps encrypted, wakes, sends POLL,
// and the controller replies with your queued command (or "nop").
// You type commands at any time — they queue up until the next wake cycle.
//
// Usage:
//   controller.exe <sleepmask.dll> [beacon.exe path]
//
// Pre-loop commands:
//   info              — show technique and target
//   set ekko/kraken   — switch technique
//   test <ms>         — one-shot self-test
//   run <ms>          — start the callback loop (e.g. run 5000)
//   exit              — quit
//
// Loop commands (typed while beacon sleeps, executed on next wake):
//   info / set ekko / set kraken — any plugin command
//   exit                         — stop the loop and quit

#include <cstdio>
#include <cstring>
#include <windows.h>

// ---- Globals ----
static HANDLE g_hWritePipe = INVALID_HANDLE_VALUE;
static HANDLE g_hReadPipe  = INVALID_HANDLE_VALUE;
static HANDLE g_hProcess   = INVALID_HANDLE_VALUE;

// ---- Command queue (protected by critical section) ----
static CRITICAL_SECTION g_queueLock;
static char  g_queuedCmd[512];
static bool  g_hasCommand = false;
static bool  g_exitRequested = false;

static DWORD WINAPI InputThread(LPVOID) {
    char input[512];
    for (;;) {
        printf("mask> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            break;

        size_t len = strlen(input);
        while (len > 0 && (input[len - 1] == '\n' || input[len - 1] == '\r'))
            input[--len] = '\0';
        if (len == 0) continue;

        EnterCriticalSection(&g_queueLock);
        if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) {
            g_exitRequested = true;
        } else {
            strncpy_s(g_queuedCmd, input, _TRUNCATE);
            g_hasCommand = true;
        }
        LeaveCriticalSection(&g_queueLock);

        if (g_exitRequested) {
            printf("[*] Exit queued — beacon will stop on next wake\n");
            break;
        }
        printf("[*] Queued: \"%s\" (executes on next wake)\n", input);
    }
    return 0;
}

// ---- Pipe I/O helpers ----
static void SendLine(const char* cmd) {
    DWORD written;
    WriteFile(g_hWritePipe, cmd, (DWORD)strlen(cmd), &written, nullptr);
    WriteFile(g_hWritePipe, "\n", 1, &written, nullptr);
}

static bool PipeReadLine(char* out, int maxLen) {
    int pos = 0;
    for (;;) {
        char ch;
        DWORD bytesRead;
        if (!ReadFile(g_hReadPipe, &ch, 1, &bytesRead, nullptr) || bytesRead == 0)
            return false;
        if (ch == '\n') {
            out[pos] = '\0';
            if (pos > 0 && out[pos - 1] == '\r') out[--pos] = '\0';
            return true;
        }
        if (pos < maxLen - 1)
            out[pos++] = ch;
    }
}

// Read and print lines until END marker
static bool ReadUntilEnd() {
    char buf[4096];
    for (;;) {
        if (!PipeReadLine(buf, sizeof(buf))) return false;
        if (strcmp(buf, "END") == 0) return true;
        printf("  %s\n", buf);
    }
}

// ---- Spawn beacon ----
static bool SpawnBeacon(const char* dllPath, const char* beaconExe) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hChildStdinRead, hChildStdinWrite;
    HANDLE hChildStdoutRead, hChildStdoutWrite;

    if (!CreatePipe(&hChildStdinRead, &hChildStdinWrite, &sa, 0)) {
        printf("[!] CreatePipe(stdin) failed: %lu\n", GetLastError());
        return false;
    }
    if (!CreatePipe(&hChildStdoutRead, &hChildStdoutWrite, &sa, 0)) {
        printf("[!] CreatePipe(stdout) failed: %lu\n", GetLastError());
        CloseHandle(hChildStdinRead);
        CloseHandle(hChildStdinWrite);
        return false;
    }

    SetHandleInformation(hChildStdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hChildStdoutRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = hChildStdinRead;
    si.hStdOutput = hChildStdoutWrite;
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

    PROCESS_INFORMATION pi{};
    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" \"%s\"", beaconExe, dllPath);

    if (!CreateProcessA(nullptr, cmdLine, nullptr, nullptr, TRUE,
                        0, nullptr, nullptr, &si, &pi)) {
        printf("[!] CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(hChildStdinRead);  CloseHandle(hChildStdinWrite);
        CloseHandle(hChildStdoutRead); CloseHandle(hChildStdoutWrite);
        return false;
    }

    CloseHandle(hChildStdinRead);
    CloseHandle(hChildStdoutWrite);
    CloseHandle(pi.hThread);

    g_hWritePipe = hChildStdinWrite;
    g_hReadPipe  = hChildStdoutRead;
    g_hProcess   = pi.hProcess;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: controller.exe <sleepmask.dll> [beacon.exe]\n");
        return 1;
    }

    const char* dllPath   = argv[1];
    const char* beaconExe = (argc >= 3) ? argv[2] : "beacon.exe";

    printf("[*] Spawning beacon: %s\n", beaconExe);
    printf("[*] DLL: %s\n", dllPath);

    if (!SpawnBeacon(dllPath, beaconExe)) {
        printf("[!] Failed to spawn beacon\n");
        return 1;
    }

    // Consume init output, wait for READY
    char line[512];
    for (;;) {
        if (!PipeReadLine(line, sizeof(line))) {
            printf("[!] Beacon died before READY\n");
            return 1;
        }
        if (strncmp(line, "READY", 5) == 0) break;
        printf("[*] %s\n", line);
    }
    printf("[+] %s\n", line);

    // Pre-loop interactive phase: configure before starting the callback loop
    printf("\nSleep Mask Controller\n");
    printf("  Pre-loop: info, set ekko, set kraken, test <ms>\n");
    printf("  Start:    run <interval_ms>  (e.g. run 10000)\n");
    printf("  Quit:     exit\n\n");

    for (;;) {
        printf("mask> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;

        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            SendLine("exit");
            PipeReadLine(line, sizeof(line));
            printf("[*] %s\n", line);
            goto cleanup;
        }

        // "run <ms>" — enter the callback loop
        if (strncmp(line, "run ", 4) == 0) {
            SendLine(line);

            // Read LOOP confirmation
            if (!PipeReadLine(line, sizeof(line))) {
                printf("[!] Beacon died\n");
                goto cleanup;
            }
            printf("[+] %s\n", line);

            // Start the input thread for queuing commands during sleep
            InitializeCriticalSection(&g_queueLock);
            HANDLE hInput = CreateThread(nullptr, 0, InputThread, nullptr, 0, nullptr);

            // Main thread: handle the beacon's sleep-poll protocol
            for (;;) {
                if (!PipeReadLine(line, sizeof(line))) {
                    printf("\n[!] Beacon disconnected\n");
                    break;
                }

                if (strcmp(line, "SLEEPING") == 0) {
                    printf("[zzz] Beacon sleeping (encrypted)...\n");
                    continue;
                }

                if (strcmp(line, "POLL") == 0) {
                    printf("[*] Beacon awake — checking queue...\n");

                    EnterCriticalSection(&g_queueLock);
                    bool hasCmd = g_hasCommand;
                    bool doExit = g_exitRequested;
                    char cmd[512] = {};
                    if (hasCmd) {
                        strncpy_s(cmd, g_queuedCmd, _TRUNCATE);
                        g_hasCommand = false;
                    }
                    LeaveCriticalSection(&g_queueLock);

                    if (doExit) {
                        SendLine("exit");
                        PipeReadLine(line, sizeof(line));
                        printf("[*] %s\n", line);
                        break;
                    }

                    if (hasCmd) {
                        printf("[>] Sending: %s\n", cmd);
                        SendLine(cmd);
                        // Read command output until END
                        if (!ReadUntilEnd()) {
                            printf("\n[!] Beacon disconnected\n");
                            break;
                        }
                    } else {
                        SendLine("nop");
                        printf("[*] No tasking — back to sleep\n");
                    }
                    continue;
                }

                if (strncmp(line, "OK", 2) == 0) {
                    printf("[*] %s\n", line);
                    break;
                }

                // Any other output from the beacon
                printf("  %s\n", line);
            }

            // Input thread is blocked in fgets — don't TerminateThread (unsafe,
            // corrupts CRT locks). Just close handles and exit; the OS cleans up.
            CloseHandle(hInput);
            DeleteCriticalSection(&g_queueLock);
            goto cleanup;
        }

        // One-shot command (pre-loop)
        SendLine(line);
        if (!ReadUntilEnd()) {
            printf("[!] Beacon disconnected\n");
            goto cleanup;
        }
    }

cleanup:
    CloseHandle(g_hWritePipe);
    CloseHandle(g_hReadPipe);
    if (g_hProcess != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(g_hProcess, 3000);
        TerminateProcess(g_hProcess, 0);
        CloseHandle(g_hProcess);
    }
    printf("[*] Done\n");
    return 0;
}
