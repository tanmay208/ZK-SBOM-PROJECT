/**
 * Barretenberg Native Windows CLI Launcher (bb.exe)
 *
 * Purpose:
 *   Provides a native Win32 PE binary for Windows hosts so Python's
 *   subprocess.run(["bb", ...], shell=False) and shutil.which("bb") can invoke
 *   the pinned Barretenberg WASM/Node CLI without requiring shell=True or WSL.
 *
 * Build Command:
 *   gcc -O2 scripts/bb_launcher.c -o .bin/bb.exe
 *   (or automated via scripts/setup_crypto_runtime.ps1)
 *
 * Prerequisites:
 *   - MinGW GCC (or MSVC / Clang) on Windows
 *   - Node.js >= 18 on PATH
 *   - Pinned dependency @aztec/bb.js@0.46.1 installed in
 *     backend/verification_service/crypto_runtime/node_modules/
 *
 * Security & Runtime Properties:
 *   - Fixed Path Resolution: Resolves relative to .bin/ directory via GetModuleFileNameA.
 *   - Injection Avoidance: Spawns Node.js via direct CreateProcessA (no cmd.exe or shell).
 *   - Exit Code Propagation: Propagates GetExitCodeProcess (0 on acceptance, 1 on reject/error).
 *   - Fail-Closed: Returns exit code 1 if CreateProcessA fails.
 *
 * Documented Limitations:
 *   - Argument Quoting: Wraps spaced arguments in double quotes; does not escape embedded
 *     quotes or trailing backslashes. Sufficient for current verifier tempfile invocations.
 *   - Executable Resolution: Passes NULL application name; Windows searches PATH for node.exe.
 *   - Error Reporting: Fails silently with exit code 1 without writing to stderr if node fails to launch.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    char *lastSlash = strrchr(exePath, '\\');
    if (lastSlash) {
        *lastSlash = '\0';
    }

    char jsPath[MAX_PATH * 2];
    snprintf(jsPath, sizeof(jsPath), "%s\\..\\backend\\verification_service\\crypto_runtime\\node_modules\\@aztec\\bb.js\\dest\\node\\main.js", exePath);

    // Build complete commandline string with quotes
    // cmdline: node "jsPath" [quoted_args...]
    char cmdline[32768];
    int offset = snprintf(cmdline, sizeof(cmdline), "node \"%s\"", jsPath);

    for (int i = 1; i < argc; i++) {
        if (strchr(argv[i], ' ') != NULL) {
            offset += snprintf(cmdline + offset, sizeof(cmdline) - offset, " \"%s\"", argv[i]);
        } else {
            offset += snprintf(cmdline + offset, sizeof(cmdline) - offset, " %s", argv[i]);
        }
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exitCode;
}
