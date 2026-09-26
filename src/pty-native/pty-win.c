/*
 * OpenLLM Windows ConPTY shim, ABI version 1.
 *
 * This translation unit is deliberately header-free, exactly like the POSIX
 * shim (pty.c): the build must stay freestanding — zero include directives —
 * because Bun's embedded TinyCC compiles on the Windows guest with no C
 * headers on its include path (Phase 0 decision, spike/PHASE0-DECISION.md).
 * Every OS symbol below is an extern declaration against kernel32 (ConPTY,
 * pipes, processes, jobs) or msvcrt (mem/str), both of which TinyCC links by
 * default on the win32 target.
 *
 * Supported target: win32-x64 ONLY. Windows on AArch64 is gated out at
 * compile time with the same fail-closed discipline pty.c uses for unknown
 * POSIX targets: the guest must never silently run a shim built for the
 * wrong ABI. On x64 there is a single calling convention, so the kernel32
 * declarations carry no __stdcall attribute; the x64 ABI passes the first
 * four arguments in registers regardless.
 *
 * Process/kill model (the retired C# sidecar semantics, ported C-side):
 *   - The child is spawned with CreatePseudoConsole + the
 *     PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attribute (EXTENDED_STARTUPINFO_PRESENT).
 *   - The whole session lives in a Job Object with
 *     JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: closing the job at destroy
 *     guarantees no orphaned grandchildren survive the handle, and
 *     TerminateJobObject implements signal 9 (SIGKILL) as an atomic tree kill.
 *   - Signal 15 (SIGTERM) is delivered with TerminateProcess on the ROOT
 *     child only — deliberately NOT GenerateConsoleCtrlEvent(CTRL_BREAK):
 *     console control events require the caller to share the target's
 *     console and reach process GROUPS through ConPTY unreliably from a
 *     non-console SYSTEM daemon, while TerminateProcess is deterministic.
 *     The TS side (windows-pty.ts) then escalates to SIGKILL after its
 *     pinned WINDOWS_PTY_KILL_GRACE_MS=250 grace window, which is what makes
 *     the rest of the tree die. Between the two steps the job object keeps
 *     stragglers contained, and ptyDestroy's job close sweeps any survivor.
 *   - ptyKill's third argument is the SAME targets bitmask as pty.c
 *     (CHILD=1, GROUP=2, FOREGROUND_GROUP=4): it is validated identically.
 *     Windows has no process groups to signal, so the group bits are
 *     subsumed by the job object; any nonzero mask routes to the same
 *     SIGTERM-root / SIGKILL-tree behaviour.
 *
 * Non-blocking host I/O model:
 *   - READS: peek-then-read. ptyPoll/ptyRead query the readable byte count
 *     with PeekNamedPipe; since that many bytes are already buffered in the
 *     pipe, the following ReadFile returns immediately and can never block
 *     the FFI call. EOF is PeekNamedPipe/ReadFile failure with
 *     ERROR_BROKEN_PIPE/ERROR_NO_DATA once the child has exited, or an empty
 *     peek with a signaled process.
 *   - WRITES: the host write end of the input pipe is an OVERLAPPED-capable
 *     named pipe (CreateNamedPipeW with FILE_FLAG_OVERLAPPED) — a plain
 *     CreatePipe handle is synchronous, and WriteFile with an OVERLAPPED on a
 *     synchronous handle executes synchronously, which would block the
 *     daemon when the child stops reading. On the overlapped named pipe,
 *     WriteFile either completes synchronously (TRUE) or returns
 *     ERROR_IO_PENDING and the byte count is tracked as in-flight until
 *     GetOverlappedResult(..., bWait=FALSE) retires it. The bounded input
 *     queue in front of the pipe is a byte-for-byte port of the pty.c queue
 *     (same watermarks, same overflow refusal), so the TS scheduler observes
 *     identical ptyWrite/ptyDrain/ptyPendingBytes/ptyBackpressured semantics
 *     on every OS.
 *
 * Wide characters: the argvBlock ABI is UTF-8, NUL-separated. Each argument
 * is converted with MultiByteToWideChar(CP_UTF8) and the command line is
 * rebuilt with the exact quoting CommandLineToArgvW inverts, because
 * CreateProcessW takes one command-line string, not an argv vector. The
 * executable path and cwd are validated as Windows-absolute (drive-letter or
 * UNC) instead of pty.c's '/' rule. The environment is emitted as a wide
 * KEY=VALUE block sorted case-insensitively by name — CreateProcessW
 * requires a sorted Unicode block — under CREATE_UNICODE_ENVIRONMENT.
 *
 * Handle discipline mirrors pty.c: a job-assignment failure after
 * CreateProcessW is fail-closed (the child is terminated and every handle is
 * closed, spawn reports the error). ptyDestroy refuses while the child is
 * unreaped (-EBUSY), exactly like the POSIX shim.
 */

#if defined(PTY_WINDOWS)
#if !defined(_WIN32) || !defined(_WIN64)
#error "PTY_WINDOWS does not match the compiler target (need win32-x64)"
#endif
#else
#error "pty-win.c supports only PTY_WINDOWS (win32-x64); AArch64 Windows is not gated in"
#endif

typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef unsigned long long uint64_t;
typedef unsigned long long size_t;
typedef uint16_t pty_wchar_t;
typedef void *pty_handle_t;

typedef int pid_t;

typedef char PtyAssertInt32[(sizeof(int32_t) == 4) ? 1 : -1];
typedef char PtyAssertInt16[(sizeof(int16_t) == 2) ? 1 : -1];
typedef char PtyAssertUint32[(sizeof(uint32_t) == 4) ? 1 : -1];
typedef char PtyAssertUint16[(sizeof(uint16_t) == 2) ? 1 : -1];
typedef char PtyAssertUint8[(sizeof(uint8_t) == 1) ? 1 : -1];
typedef char PtyAssertPointer[(sizeof(void *) == 8) ? 1 : -1];
typedef char PtyAssertSizeT[(sizeof(size_t) == 8) ? 1 : -1];
typedef char PtyAssertWchar[(sizeof(pty_wchar_t) == 2) ? 1 : -1];

#define PTY_NULL ((void *)0)
#define PTY_INT32_MAX 2147483647
#define PTY_UINT32_MAX 4294967295U
#define PTY_SIZE_MAX ((size_t)-1)

/* Bounded input queue — identical limits to pty.c (ABI contract). */
#define PTY_QUEUE_HIGH_WATER 65536U
#define PTY_QUEUE_LOW_WATER 16384U
#define PTY_QUEUE_MAX 262144U

/* Single overlapped write chunk bound; bounds in-flight bytes per handle. */
#define PTY_WIN_WRITE_CHUNK 65536U

/* Stable shim errno table — identical numbering to pty.c so the TS caller
 * keys on one value set across all three OSes. */
#define PTY_EPERM 1
#define PTY_ENOENT 2
#define PTY_ESRCH 3
#define PTY_EINTR 4
#define PTY_EIO 5
#define PTY_E2BIG 7
#define PTY_EBADF 9
#define PTY_ECHILD 10
#define PTY_EAGAIN 11
#define PTY_ENOMEM 12
#define PTY_EBUSY 16
#define PTY_EINVAL 22
#define PTY_EMFILE 24
#define PTY_EPIPE 32
/* No native Windows ECANCELED; pinned to the shim's stable value (the
 * Darwin numbering, matching pty.c's per-target table). */
#define PTY_ECANCELED 89

#define PTY_KILL_CHILD 1U
#define PTY_KILL_ORIGINAL_GROUP 2U
#define PTY_KILL_FOREGROUND_GROUP 4U
#define PTY_KILL_ALL_TARGETS 7U

#define PTY_WIN_INFINITE 0xFFFFFFFFUL
#define PTY_WIN_WAIT_OBJECT_0 0UL
#define PTY_WIN_WAIT_TIMEOUT 0x00000102UL

#define PTY_WIN_ERROR_FILE_NOT_FOUND 2UL
#define PTY_WIN_ERROR_PATH_NOT_FOUND 3UL
#define PTY_WIN_ERROR_ACCESS_DENIED 5UL
#define PTY_WIN_ERROR_NOT_ENOUGH_MEMORY 8UL
#define PTY_WIN_ERROR_OUT_OF_MEMORY 14UL
#define PTY_WIN_ERROR_INVALID_HANDLE 6UL
#define PTY_WIN_ERROR_NOT_FOUND 1168UL
#define PTY_WIN_ERROR_INVALID_PARAMETER 87UL
#define PTY_WIN_ERROR_BROKEN_PIPE 109UL
#define PTY_WIN_ERROR_INSUFFICIENT_BUFFER 122UL
#define PTY_WIN_ERROR_NO_DATA 232UL
#define PTY_WIN_ERROR_IO_INCOMPLETE 996UL
#define PTY_WIN_ERROR_OPERATION_ABORTED 995UL
#define PTY_WIN_ERROR_IO_INCOMPLETE 996UL
#define PTY_WIN_ERROR_IO_PENDING 997UL
#define PTY_WIN_ERROR_BAD_EXE_FORMAT 193UL

#define PTY_WIN_CP_UTF8 65001U

#define PTY_WIN_CREATE_UNICODE_ENVIRONMENT 0x00000400UL
#define PTY_WIN_CREATE_SUSPENDED 0x00000004UL
#define PTY_WIN_EXTENDED_STARTUPINFO_PRESENT 0x00080000UL

/* ProcThreadAttributeValue(Number, Thread, Input, Additive) = Number |
 * (Input ? 0x20000 : 0). HandleList is ProcThreadAttribute number 3, so
 * 3 | 0x20000 = 0x20003; PSEUDOCONSOLE is number 22, so 22 | 0x20000. */
#define PTY_WIN_STARTF_USESTDHANDLES 0x00000100UL

/* PROC_THREAD_ATTRIBUTE_HANDLE_LIST (0x00020003ULL) intentionally unused:
 * see the P3-3 guest finding at the spawn site below. */
#define PTY_WIN_PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016ULL

/* Named-pipe surface for the non-blocking host write end. A CreatePipe
 * handle is synchronous: WriteFile with an OVERLAPPED on it would execute
 * synchronously and block the daemon, so the input pipe's host end is a
 * FILE_FLAG_OVERLAPPED named pipe instead. */
#define PTY_WIN_INVALID_HANDLE_VALUE \
    ((pty_handle_t)(uint64_t)0xFFFFFFFFFFFFFFFFULL)
#define PTY_WIN_GENERIC_READ 0x80000000UL
#define PTY_WIN_FILE_ATTRIBUTE_NORMAL 0x00000080UL
#define PTY_WIN_FILE_FLAG_OVERLAPPED 0x40000000UL
#define PTY_WIN_FILE_FLAG_FIRST_PIPE_INSTANCE 0x00080000UL
#define PTY_WIN_PIPE_ACCESS_OUTBOUND 0x00000002UL
#define PTY_WIN_PIPE_TYPE_BYTE 0x00000000UL
#define PTY_WIN_PIPE_WAIT 0x00000000UL
#define PTY_WIN_PIPE_REJECT_REMOTE_CLIENTS 0x00000008UL
#define PTY_WIN_OPEN_EXISTING 3UL

#define PTY_WIN_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION 9
#define PTY_WIN_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 0x00002000UL

#define PTY_WIN_SIGKILL 9
#define PTY_WIN_SIGTERM 15
/* Exit codes mirror the POSIX wait status convention (128 + signal). */
#define PTY_WIN_EXIT_SIGKILL 137
#define PTY_WIN_EXIT_SIGTERM 143

/* ------------------------------------------------------------------ */
/* Hand-written Win32 ABI layouts (verified against the documented     */
/* x64 layouts; every layout carries a sizeof compile-time assert).    */
/* ------------------------------------------------------------------ */

typedef struct PtySecurityAttributes {
    uint32_t nLength;
    uint32_t pad0;
    void *lpSecurityDescriptor;
    int32_t bInheritHandle;
    uint32_t pad1;
} PtySecurityAttributes;

/* STARTUPINFOW, x64 layout: 104 bytes. */
typedef struct PtyStartupInfoW {
    uint32_t cb;
    uint32_t pad0;
    pty_wchar_t *lpReserved;
    pty_wchar_t *lpDesktop;
    pty_wchar_t *lpTitle;
    uint32_t dwX;
    uint32_t dwY;
    uint32_t dwXSize;
    uint32_t dwYSize;
    uint32_t dwXCountChars;
    uint32_t dwYCountChars;
    uint32_t dwFillAttribute;
    uint32_t dwFlags;
    uint16_t wShowWindow;
    uint16_t cbReserved2;
    uint32_t pad1;
    uint8_t *lpReserved2;
    pty_handle_t hStdInput;
    pty_handle_t hStdOutput;
    pty_handle_t hStdError;
} PtyStartupInfoW;

typedef struct PtyStartupInfoExW {
    PtyStartupInfoW startupInfo;
    void *lpAttributeList;
} PtyStartupInfoExW;

typedef struct PtyProcessInformation {
    pty_handle_t hProcess;
    pty_handle_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} PtyProcessInformation;

typedef struct PtyOverlapped {
    uint64_t internal;
    uint64_t internalHigh;
    uint32_t offset;
    uint32_t offsetHigh;
    pty_handle_t hEvent;
} PtyOverlapped;

typedef struct PtyJobObjectBasicLimitInformation {
    uint64_t perProcessUserTimeLimit;
    uint64_t perJobUserTimeLimit;
    uint32_t limitFlags;
    uint32_t pad0;
    size_t minimumWorkingSetSize;
    size_t maximumWorkingSetSize;
    uint32_t activeProcessLimit;
    uint32_t pad1;
    uint64_t affinity;
    uint32_t priorityClass;
    uint32_t schedulingClass;
} PtyJobObjectBasicLimitInformation;

typedef struct PtyIoCounters {
    uint64_t readOperationCount;
    uint64_t writeOperationCount;
    uint64_t otherOperationCount;
    uint64_t readTransferCount;
    uint64_t writeTransferCount;
    uint64_t otherTransferCount;
} PtyIoCounters;

/* JOBOBJECT_EXTENDED_LIMIT_INFORMATION, x64 layout: 144 bytes. */
typedef struct PtyJobObjectExtendedLimitInformation {
    PtyJobObjectBasicLimitInformation basicLimitInformation;
    PtyIoCounters ioInfo;
    size_t processMemoryLimit;
    size_t jobMemoryLimit;
    size_t peakProcessMemoryUsed;
    size_t peakJobMemoryUsed;
} PtyJobObjectExtendedLimitInformation;

/* COORD is passed to CreatePseudoConsole/ResizePseudoConsole BY VALUE. */
typedef struct PtyConsoleSize {
    int16_t x;
    int16_t y;
} PtyConsoleSize;

typedef short pty_i16_t;

typedef char PtyAssertSecurityAttributes[
    (sizeof(PtySecurityAttributes) == 24) ? 1 : -1];
typedef char PtyAssertStartupInfoW[(sizeof(PtyStartupInfoW) == 104) ? 1 : -1];
typedef char PtyAssertStartupInfoExW[
    (sizeof(PtyStartupInfoExW) == 112) ? 1 : -1];
typedef char PtyAssertProcessInformation[
    (sizeof(PtyProcessInformation) == 24) ? 1 : -1];
typedef char PtyAssertOverlapped[(sizeof(PtyOverlapped) == 32) ? 1 : -1];
typedef char PtyAssertJobLimits[
    (sizeof(PtyJobObjectExtendedLimitInformation) == 144) ? 1 : -1];
typedef char PtyAssertIoCounters[(sizeof(PtyIoCounters) == 48) ? 1 : -1];
typedef char PtyAssertConsoleSize[(sizeof(PtyConsoleSize) == 4) ? 1 : -1];
typedef char PtyAssertJobLimitFlagsOffset[
    ((size_t)((const char *)&((PtyJobObjectExtendedLimitInformation *)0)
                  ->basicLimitInformation.limitFlags -
              (const char *)0) == 16)
        ? 1
        : -1];
typedef char PtyAssertStartupInfoCbOffset[
    ((size_t)((const char *)&((PtyStartupInfoExW *)0)->startupInfo.cb -
              (const char *)0) == 0)
        ? 1
        : -1];
typedef char PtyAssertStartupInfoExListOffset[
    ((size_t)((const char *)&((PtyStartupInfoExW *)0)->lpAttributeList -
              (const char *)0) == 104)
        ? 1
        : -1];
typedef char PtyAssertProcessInformationPidOffset[
    ((size_t)((const char *)&((PtyProcessInformation *)0)->dwProcessId -
              (const char *)0) == 16)
        ? 1
        : -1];

/* ------------------------------------------------------------------ */
/* Freestanding extern surface.                                        */
/* ------------------------------------------------------------------ */

extern void *malloc(size_t size);
extern void *calloc(size_t count, size_t size);
extern void *realloc(void *pointer, size_t size);
extern void free(void *pointer);
extern void *memcpy(void *destination, const void *source, size_t length);
extern void *memmove(void *destination, const void *source, size_t length);
extern void *memset(void *destination, int32_t fill, size_t length);
extern size_t strlen(const char *value);

/* kernel32 */
extern long CreatePseudoConsole(
    PtyConsoleSize size,
    pty_handle_t hInput,
    pty_handle_t hOutput,
    uint32_t dwFlags,
    pty_handle_t *phPC
);
extern long ResizePseudoConsole(pty_handle_t hPC, PtyConsoleSize size);
extern void ClosePseudoConsole(pty_handle_t hPC);

extern int32_t CreatePipe(
    pty_handle_t *hReadPipe,
    pty_handle_t *hWritePipe,
    PtySecurityAttributes *lpPipeAttributes,
    uint32_t nSize
);
extern pty_handle_t CreateNamedPipeW(
    const pty_wchar_t *lpName,
    uint32_t dwOpenMode,
    uint32_t dwPipeMode,
    uint32_t nMaxInstances,
    uint32_t nOutBufferSize,
    uint32_t nInBufferSize,
    uint32_t nDefaultTimeOut,
    PtySecurityAttributes *lpSecurityAttributes
);
extern pty_handle_t CreateFileW(
    const pty_wchar_t *lpFileName,
    uint32_t dwDesiredAccess,
    uint32_t dwShareMode,
    PtySecurityAttributes *lpSecurityAttributes,
    uint32_t dwCreationDisposition,
    uint32_t dwFlagsAndAttributes,
    pty_handle_t hTemplateFile
);
extern uint32_t GetCurrentProcessId(void);
extern int32_t PeekNamedPipe(
    pty_handle_t hPipe,
    void *lpBuffer,
    uint32_t nBufferSize,
    uint32_t *lpBytesRead,
    uint32_t *lpTotalBytesAvail,
    uint32_t *lpBytesLeftThisMessage
);
extern int32_t ReadFile(
    pty_handle_t hFile,
    void *lpBuffer,
    uint32_t nNumberOfBytesToRead,
    uint32_t *lpNumberOfBytesRead,
    PtyOverlapped *lpOverlapped
);
extern int32_t WriteFile(
    pty_handle_t hFile,
    const void *lpBuffer,
    uint32_t nNumberOfBytesToWrite,
    uint32_t *lpNumberOfBytesWritten,
    PtyOverlapped *lpOverlapped
);
extern int32_t GetOverlappedResult(
    pty_handle_t hFile,
    PtyOverlapped *lpOverlapped,
    uint32_t *lpNumberOfBytesTransferred,
    int32_t bWait
);
extern int32_t CancelIoEx(pty_handle_t hFile, PtyOverlapped *lpOverlapped);

extern uint32_t GetLastError(void);
extern void SetLastError(uint32_t dwErrCode);

extern int32_t CreateProcessW(
    const pty_wchar_t *lpApplicationName,
    pty_wchar_t *lpCommandLine,
    void *lpProcessAttributes,
    void *lpThreadAttributes,
    int32_t bInheritHandles,
    uint32_t dwCreationFlags,
    void *lpEnvironment,
    const pty_wchar_t *lpCurrentDirectory,
    PtyStartupInfoExW *lpStartupInfo,
    PtyProcessInformation *lpProcessInformation
);
extern uint32_t ResumeThread(pty_handle_t hThread);
extern int32_t InitializeProcThreadAttributeList(
    void *lpAttributeList,
    uint32_t dwAttributeCount,
    uint32_t dwFlags,
    size_t *lpSize
);
extern int32_t UpdateProcThreadAttribute(
    void *lpAttributeList,
    uint32_t dwFlags,
    uint64_t attribute,
    void *lpValue,
    size_t cbSize,
    void *lpPreviousValue,
    void *lpReturnSize
);
extern void DeleteProcThreadAttributeList(void *lpAttributeList);
extern int32_t SetHandleInformation(
    pty_handle_t hObject,
    uint32_t dwMask,
    uint32_t dwFlags
);

extern pty_handle_t CreateJobObjectW(
    void *lpJobAttributes,
    const pty_wchar_t *lpName
);
extern int32_t SetInformationJobObject(
    pty_handle_t hJob,
    int32_t jobObjectInfoClass,
    void *lpJobObjectInfo,
    uint32_t cbJobObjectInfoLength
);
extern int32_t AssignProcessToJobObject(
    pty_handle_t hJob,
    pty_handle_t hProcess
);
extern int32_t TerminateJobObject(pty_handle_t hJob, uint32_t uExitCode);
extern int32_t TerminateProcess(
    pty_handle_t hProcess,
    uint32_t uExitCode
);

extern uint32_t WaitForSingleObject(
    pty_handle_t hHandle,
    uint32_t dwMilliseconds
);
extern int32_t GetExitCodeProcess(
    pty_handle_t hProcess,
    uint32_t *lpExitCode
);
extern int32_t CloseHandle(pty_handle_t hObject);

extern int32_t MultiByteToWideChar(
    uint32_t codePage,
    uint32_t dwFlags,
    const char *lpMultiByteStr,
    int32_t cbMultiByte,
    pty_wchar_t *lpWideCharStr,
    int32_t cchWideChar
);

/* ------------------------------------------------------------------ */
/* Handle table (identical discipline to pty.c).                       */
/* ------------------------------------------------------------------ */

typedef struct PtyEnvEntry {
    char *name;
    char *value;
} PtyEnvEntry;

typedef struct PtyHandle {
    int32_t id;
    int32_t spawnStarted;
    int32_t spawnStatus;

    pid_t pid;
    int32_t childReaped;
    int32_t childLost;
    int32_t waitExitCode;
    int32_t waitSignal;
    int32_t lastIssuedKillSignal;

    pty_handle_t pseudoConsole;
    pty_handle_t pipeInWrite;
    pty_handle_t pipeOutRead;
    pty_handle_t processHandle;
    pty_handle_t jobHandle;
    int32_t writeInFlight;
#ifdef PTY_TESTING
    uint32_t testCompletionPending;
#endif
    PtyOverlapped writeOverlapped;
#ifdef PTY_TESTING
    uint32_t testCancelError;
#endif

    PtyEnvEntry *environment;
    uint32_t environmentCount;
    uint32_t environmentCapacity;

    uint8_t pendingInput[PTY_QUEUE_MAX];
    uint32_t pendingLength;
    int32_t inputBackpressured;
    int32_t fatalIoErrno;

    struct PtyHandle *next;
} PtyHandle;

static PtyHandle *ptyHandles = (PtyHandle *)PTY_NULL;
static uint32_t ptyNextHandle = 1U;
static uint32_t ptyNextPipeName = 1U;

static PtyHandle *pty_find_handle(int32_t handle) {
    PtyHandle *current = ptyHandles;
    if (handle <= 0) return (PtyHandle *)PTY_NULL;
    while (current != (PtyHandle *)PTY_NULL) {
        if (current->id == handle) return current;
        current = current->next;
    }
    return (PtyHandle *)PTY_NULL;
}

static char *pty_copy_string(const char *value) {
    size_t length;
    char *copy;
    if (value == (const char *)PTY_NULL) return (char *)PTY_NULL;
    length = strlen(value);
    if (length == PTY_SIZE_MAX) return (char *)PTY_NULL;
    copy = (char *)malloc(length + 1U);
    if (copy == (char *)PTY_NULL) return (char *)PTY_NULL;
    memcpy(copy, value, length + 1U);
    return copy;
}

static void pty_free_environment(PtyHandle *handle) {
    uint32_t index;
    for (index = 0U; index < handle->environmentCount; index += 1U) {
        free(handle->environment[index].name);
        free(handle->environment[index].value);
    }
    free(handle->environment);
    handle->environment = (PtyEnvEntry *)PTY_NULL;
    handle->environmentCount = 0U;
    handle->environmentCapacity = 0U;
}

static int32_t pty_close_handle(pty_handle_t *handleValue) {
    pty_handle_t owned;
    if (*handleValue == (pty_handle_t)PTY_NULL) return 0;
    owned = *handleValue;
    *handleValue = (pty_handle_t)PTY_NULL;
    if (CloseHandle(owned) == 0) return -PTY_EIO;
    return 0;
}

static int32_t pty_win_map_last_error(uint32_t code) {
    switch (code) {
        case PTY_WIN_ERROR_FILE_NOT_FOUND:
        case PTY_WIN_ERROR_PATH_NOT_FOUND:
            return PTY_ENOENT;
        case PTY_WIN_ERROR_ACCESS_DENIED:
            return PTY_EPERM;
        case PTY_WIN_ERROR_NOT_ENOUGH_MEMORY:
        case PTY_WIN_ERROR_OUT_OF_MEMORY:
        case PTY_WIN_ERROR_INSUFFICIENT_BUFFER:
            return PTY_ENOMEM;
        case PTY_WIN_ERROR_INVALID_HANDLE:
            return PTY_EBADF;
        case PTY_WIN_ERROR_INVALID_PARAMETER:
            return PTY_EINVAL;
        default:
            return PTY_EIO;
    }
}

static int32_t pty_win_last_error(void) {
    uint32_t code = GetLastError();
    if (code == 0U) return -PTY_EIO;
    return -pty_win_map_last_error(code);
}

static int32_t pty_win_path_is_absolute(const char *path) {
    char first;
    char third;
    if (path == (const char *)PTY_NULL) return 0;
    first = path[0];
    if (first == '\0') return 0;
    if (path[1] == '\0') return 0;
    /* Drive-letter absolute: C:\... or C:/... */
    if (((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z')) &&
        path[1] == ':') {
        third = path[2];
        if (third == '\\' || third == '/') return 1;
        return 0;
    }
    /* UNC absolute: \\server\share */
    if (first == '\\' && path[1] == '\\') return 1;
    return 0;
}

static int32_t pty_win_ascii_compare_folded(const char *left, const char *right) {
    for (;;) {
        char a = *left;
        char b = *right;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return (int32_t)(uint8_t)a - (int32_t)(uint8_t)b;
        if (a == '\0') return 0;
        left += 1;
        right += 1;
    }
}

static void pty_remove_pending_prefix(PtyHandle *handle, uint32_t count) {
    if (count >= handle->pendingLength) {
        handle->pendingLength = 0U;
        return;
    }
    memmove(
        handle->pendingInput,
        handle->pendingInput + count,
        (size_t)(handle->pendingLength - count)
    );
    handle->pendingLength -= count;
}

static int32_t pty_record_fatal_io(PtyHandle *handle, int32_t fallback) {
    int32_t errorNumber = fallback;
    handle->fatalIoErrno = errorNumber;
    return -errorNumber;
}

/* ------------------------------------------------------------------ */
/* Write pump: one in-flight OVERLAPPED write per handle, never        */
/* blocking the FFI call. Returns 1 when fully drained, 0 when the     */
/* pipe is full (in flight), or -errno on a fatal pipe error.          */
/* ------------------------------------------------------------------ */
static int32_t pty_win_pump_writes(PtyHandle *handle) {
    for (;;) {
        if (handle->writeInFlight > 0) {
            uint32_t transferred = 0U;
            if (GetOverlappedResult(
                    handle->pipeInWrite,
                    &handle->writeOverlapped,
                    &transferred,
                    0
                ) == 0) {
                uint32_t errorCode = GetLastError();
                if (errorCode == PTY_WIN_ERROR_IO_INCOMPLETE) return 0;
                handle->writeInFlight = 0;
                if (errorCode == PTY_WIN_ERROR_OPERATION_ABORTED ||
                    errorCode == PTY_WIN_ERROR_BROKEN_PIPE ||
                    errorCode == PTY_WIN_ERROR_NO_DATA ||
                    errorCode == PTY_WIN_ERROR_INVALID_HANDLE)
                    return pty_record_fatal_io(handle, PTY_EPIPE);
                return pty_record_fatal_io(handle, PTY_EIO);
            }
            /* A single byte-pipe write completes in full when it completes;
             * anything else is unrecoverable (the issued bytes already left
             * the queue), so it is a fatal I/O error, exactly like pty.c
             * treating a zero-length write as EIO. */
            if (transferred != (uint32_t)handle->writeInFlight) {
                handle->writeInFlight = 0;
                return pty_record_fatal_io(handle, PTY_EIO);
            }
            handle->writeInFlight = 0;
            continue;
        }
        if (handle->pendingLength == 0U) return 1;
        {
            uint32_t chunk = handle->pendingLength > PTY_WIN_WRITE_CHUNK
                ? PTY_WIN_WRITE_CHUNK
                : handle->pendingLength;
            uint32_t written = 0U;
            memset(&handle->writeOverlapped, 0, sizeof(PtyOverlapped));
            if (WriteFile(
                    handle->pipeInWrite,
                    handle->pendingInput,
                    chunk,
                    &written,
                    &handle->writeOverlapped
                ) != 0) {
                if (written == 0U)
                    return pty_record_fatal_io(handle, PTY_EIO);
                pty_remove_pending_prefix(handle, written);
                continue;
            }
            {
                uint32_t errorCode = GetLastError();
                if (errorCode == PTY_WIN_ERROR_IO_PENDING) {
                    handle->writeInFlight = (int32_t)chunk;
                    pty_remove_pending_prefix(handle, chunk);
                    return 0;
                }
                if (errorCode == PTY_WIN_ERROR_BROKEN_PIPE ||
                    errorCode == PTY_WIN_ERROR_NO_DATA ||
                    errorCode == PTY_WIN_ERROR_OPERATION_ABORTED ||
                    errorCode == PTY_WIN_ERROR_INVALID_HANDLE)
                    return pty_record_fatal_io(handle, PTY_EPIPE);
                return pty_record_fatal_io(handle, PTY_EIO);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Wide-string helpers for the CreateProcessW surface.                 */
/* ------------------------------------------------------------------ */

static int32_t pty_win_utf8_to_wide(
    const char *utf8Value,
    pty_wchar_t *wideBuffer,
    int32_t wideCapacity
) {
    return MultiByteToWideChar(
        PTY_WIN_CP_UTF8,
        0U,
        utf8Value,
        -1,
        wideBuffer,
        wideCapacity
    );
}

/* UTF-8 -> UTF-16, allocating. Returns NULL on failure (ENOMEM). */
static pty_wchar_t *pty_win_utf8_to_wide_alloc(const char *utf8Value) {
    int32_t count = pty_win_utf8_to_wide(utf8Value, (pty_wchar_t *)PTY_NULL, 0);
    pty_wchar_t *converted;
    if (count <= 0) return (pty_wchar_t *)PTY_NULL;
    converted = (pty_wchar_t *)malloc((size_t)count * sizeof(pty_wchar_t));
    if (converted == (pty_wchar_t *)PTY_NULL) return (pty_wchar_t *)PTY_NULL;
    if (pty_win_utf8_to_wide(utf8Value, converted, count) <= 0) {
        free(converted);
        return (pty_wchar_t *)PTY_NULL;
    }
    return converted;
}

/* Append a decimal uint32 to a wide buffer; returns the new cursor. The pipe
 * name is built by hand (no swprintf in the freestanding surface). */
static uint32_t pty_win_append_wide_uint(
    pty_wchar_t *buffer,
    uint32_t cursor,
    uint32_t value
) {
    pty_wchar_t digits[10];
    uint32_t count = 0U;
    uint32_t index;
    do {
        digits[count] = (pty_wchar_t)((uint8_t)'0' + (value % 10U));
        value /= 10U;
        count += 1U;
    } while (value > 0U);
    for (index = 0U; index < count; index += 1U)
        buffer[cursor + index] = digits[count - 1U - index];
    return cursor + count;
}

static int32_t pty_win_is_path_separator(pty_wchar_t value) {
    return value == (pty_wchar_t)' ' || value == (pty_wchar_t)'\t';
}

/*
 * Append one argument with the exact quoting CommandLineToArgvW inverts:
 * wrap in quotes when empty or containing space/tab; backslash runs double
 * before a literal quote, and a trailing backslash run doubles inside the
 * quotes.
 */
static void pty_win_append_quoted_argument(
    pty_wchar_t *commandLine,
    uint32_t *cursor,
    const pty_wchar_t *argument
) {
    uint32_t index = 0U;
    int32_t needsQuotes = argument[0] == (pty_wchar_t)'\0';
    uint32_t backslashes = 0U;
    while (argument[index] != (pty_wchar_t)'\0') {
        if (pty_win_is_path_separator(argument[index])) needsQuotes = 1;
        index += 1U;
    }
    if (!needsQuotes) {
        index = 0U;
        while (argument[index] != (pty_wchar_t)'\0') {
            commandLine[*cursor] = argument[index];
            *cursor += 1U;
            index += 1U;
        }
        commandLine[*cursor] = (pty_wchar_t)'\0';
        return;
    }
    commandLine[*cursor] = (pty_wchar_t)'"';
    *cursor += 1U;
    index = 0U;
    while (argument[index] != (pty_wchar_t)'\0') {
        pty_wchar_t current = argument[index];
        if (current == (pty_wchar_t)'\\') {
            backslashes += 1U;
            index += 1U;
            continue;
        }
        if (current == (pty_wchar_t)'"') {
            while (backslashes > 0U) {
                commandLine[*cursor] = (pty_wchar_t)'\\';
                *cursor += 1U;
                commandLine[*cursor] = (pty_wchar_t)'\\';
                *cursor += 1U;
                backslashes -= 1U;
            }
            commandLine[*cursor] = (pty_wchar_t)'\\';
            *cursor += 1U;
            commandLine[*cursor] = (pty_wchar_t)'"';
            *cursor += 1U;
            index += 1U;
            continue;
        }
        while (backslashes > 0U) {
            commandLine[*cursor] = (pty_wchar_t)'\\';
            *cursor += 1U;
            backslashes -= 1U;
        }
        commandLine[*cursor] = current;
        *cursor += 1U;
        index += 1U;
    }
    while (backslashes > 0U) {
        commandLine[*cursor] = (pty_wchar_t)'\\';
        *cursor += 1U;
        commandLine[*cursor] = (pty_wchar_t)'\\';
        *cursor += 1U;
        backslashes -= 1U;
    }
    commandLine[*cursor] = (pty_wchar_t)'"';
    *cursor += 1U;
    commandLine[*cursor] = (pty_wchar_t)'\0';
}

static int32_t pty_prepare_argv(
    char ***argvOut,
    const uint8_t *argvBlock,
    uint32_t argvBytes,
    uint32_t argc
) {
    uint32_t index;
    uint32_t offset = 0U;
    uint32_t argument = 0U;
    char **argv;
    uint8_t *storage;

    *argvOut = (char **)PTY_NULL;
    if (argc == 0U || argvBytes == 0U || argvBlock == (const uint8_t *)PTY_NULL)
        return -PTY_EINVAL;
    if (argc > (uint32_t)PTY_INT32_MAX || argvBytes > (uint32_t)PTY_INT32_MAX)
        return -PTY_E2BIG;
    if ((size_t)argc + 1U > PTY_SIZE_MAX / sizeof(char *)) return -PTY_E2BIG;

    for (index = 0U; index < argvBytes; index += 1U) {
        if (argvBlock[index] == 0U) {
            argument += 1U;
            if (argument > argc) return -PTY_EINVAL;
        }
    }
    if (argument != argc || argvBlock[argvBytes - 1U] != 0U) return -PTY_EINVAL;

    storage = (uint8_t *)malloc((size_t)argvBytes);
    if (storage == (uint8_t *)PTY_NULL) return -PTY_ENOMEM;
    memcpy(storage, argvBlock, (size_t)argvBytes);

    argv = (char **)calloc((size_t)argc + 1U, sizeof(char *));
    if (argv == (char **)PTY_NULL) {
        free(storage);
        return -PTY_ENOMEM;
    }
    for (argument = 0U; argument < argc; argument += 1U) {
        argv[argument] = (char *)(storage + offset);
        while (offset < argvBytes && storage[offset] != 0U) offset += 1U;
        if (offset >= argvBytes) {
            free(storage);
            free(argv);
            return -PTY_EINVAL;
        }
        offset += 1U;
    }
    if (offset != argvBytes) {
        free(storage);
        free(argv);
        return -PTY_EINVAL;
    }
    argv[argc] = (char *)PTY_NULL;
    *argvOut = argv;
    return 0;
}

/* ------------------------------------------------------------------ */
/* ABI entry points — same symbol table and return conventions as      */
/* pty.c: negative returns are negated shim-errno values.              */
/* ------------------------------------------------------------------ */

int32_t ptyAbiVersion(void) {
    return 1;
}

int32_t ptyQueueLimits(uint32_t *out3) {
    if (out3 == (uint32_t *)PTY_NULL) return -PTY_EINVAL;
    out3[0] = PTY_QUEUE_HIGH_WATER;
    out3[1] = PTY_QUEUE_LOW_WATER;
    out3[2] = PTY_QUEUE_MAX;
    return 0;
}

int32_t ptyCreate(void) {
    PtyHandle *handle;
    uint32_t id;
    if (ptyNextHandle == 0U || ptyNextHandle > (uint32_t)PTY_INT32_MAX)
        return -PTY_EMFILE;
    handle = (PtyHandle *)calloc(1U, sizeof(PtyHandle));
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_ENOMEM;
    id = ptyNextHandle;
    ptyNextHandle += 1U;
    handle->id = (int32_t)id;
    handle->next = ptyHandles;
    ptyHandles = handle;
    return handle->id;
}

int32_t ptySetEnv(int32_t handleId, const char *name, const char *value) {
    PtyHandle *handle = pty_find_handle(handleId);
    uint32_t index;
    size_t cursor;
    char *nameCopy;
    char *valueCopy;
    size_t nameLength;

    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->spawnStarted) return -PTY_EBUSY;
    if (name == (const char *)PTY_NULL || name[0] == '\0') return -PTY_EINVAL;
    nameLength = strlen(name);
    for (cursor = 0U; cursor < nameLength; cursor += 1U) {
        if (name[cursor] == '=') return -PTY_EINVAL;
    }

    for (index = 0U; index < handle->environmentCount; index += 1U) {
        size_t existingLength = strlen(handle->environment[index].name);
        if (existingLength == nameLength) {
            size_t compareCursor;
            int32_t same = 1;
            for (compareCursor = 0U; compareCursor < nameLength; compareCursor += 1U) {
                if (handle->environment[index].name[compareCursor] != name[compareCursor]) {
                    same = 0;
                    break;
                }
            }
            if (same) {
                if (value == (const char *)PTY_NULL) {
                    free(handle->environment[index].name);
                    free(handle->environment[index].value);
                    if (index + 1U < handle->environmentCount) {
                        memmove(
                            handle->environment + index,
                            handle->environment + index + 1U,
                            (size_t)(handle->environmentCount - index - 1U) *
                                sizeof(PtyEnvEntry)
                        );
                    }
                    handle->environmentCount -= 1U;
                    return 0;
                }
                valueCopy = pty_copy_string(value);
                if (valueCopy == (char *)PTY_NULL) return -PTY_ENOMEM;
                free(handle->environment[index].value);
                handle->environment[index].value = valueCopy;
                return 0;
            }
        }
    }

    if (value == (const char *)PTY_NULL) return 0;
    if (handle->environmentCount == handle->environmentCapacity) {
        uint32_t newCapacity = handle->environmentCapacity == 0U
            ? 8U
            : handle->environmentCapacity * 2U;
        PtyEnvEntry *replacement;
        if (newCapacity < handle->environmentCapacity ||
            (size_t)newCapacity > PTY_SIZE_MAX / sizeof(PtyEnvEntry))
            return -PTY_E2BIG;
        replacement = (PtyEnvEntry *)realloc(
            handle->environment,
            (size_t)newCapacity * sizeof(PtyEnvEntry)
        );
        if (replacement == (PtyEnvEntry *)PTY_NULL) return -PTY_ENOMEM;
        handle->environment = replacement;
        handle->environmentCapacity = newCapacity;
    }

    nameCopy = pty_copy_string(name);
    if (nameCopy == (char *)PTY_NULL) return -PTY_ENOMEM;
    valueCopy = pty_copy_string(value);
    if (valueCopy == (char *)PTY_NULL) {
        free(nameCopy);
        return -PTY_ENOMEM;
    }
    handle->environment[handle->environmentCount].name = nameCopy;
    handle->environment[handle->environmentCount].value = valueCopy;
    handle->environmentCount += 1U;
    return 0;
}

/* P3-3 guest finding: bun 1.4.1's TinyCC (win32-x64) mis-reads stack-passed
 * parameters (args 5+) when the callee has a large local frame — verified on
 * the win11 guest: argvBytes/argc arrived corrupted in ptySpawn and a minimal
 * 4 KiB-frame probe segfaulted inside the FFI call. ptySpawn is the only
 * export with stack-passed parameters, so its large locals live in ONE heap
 * scratch block; the frame stays small and every exit path frees it. */
typedef struct PtySpawnScratch {
    PtyStartupInfoExW startupInfo;
    PtyProcessInformation processInfo;
    PtyJobObjectExtendedLimitInformation jobLimits;
    pty_wchar_t pipeName[64];
} PtySpawnScratch;

int32_t ptySpawn(
    int32_t handleId,
    const char *executable,
    const char *cwd,
    const uint8_t *argvBlock,
    uint32_t argvBytes,
    uint32_t argc,
    uint32_t cols,
    uint32_t rows
) {
    PtyHandle *handle = pty_find_handle(handleId);
    char **argv = (char **)PTY_NULL;
    uint8_t *argvStorage = (uint8_t *)PTY_NULL;
    pty_wchar_t *commandLine = (pty_wchar_t *)PTY_NULL;
    pty_wchar_t *executableWide = (pty_wchar_t *)PTY_NULL;
    pty_wchar_t *cwdWide = (pty_wchar_t *)PTY_NULL;
    pty_wchar_t *environmentBlock = (pty_wchar_t *)PTY_NULL;
    uint32_t *sortedIndex = (uint32_t *)PTY_NULL;
    void *attributeList = PTY_NULL;
    size_t attributeListSize = 0U;
    PtySecurityAttributes pipeAttributes;
    PtyConsoleSize consoleSize;
    PtySpawnScratch *scratch = (PtySpawnScratch *)PTY_NULL;
    pty_handle_t pipeInRead = (pty_handle_t)PTY_NULL;
    pty_handle_t pipeOutWrite = (pty_handle_t)PTY_NULL;
    pty_handle_t jobObject = (pty_handle_t)PTY_NULL;
    uint32_t cursor;
    uint32_t argument;
    uint32_t index;
    uint32_t resumeResult;
    int32_t result;

    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->spawnStarted) return -PTY_EBUSY;
    handle->spawnStarted = 1;
    if (cols == 0U || cols > 65535U || rows == 0U || rows > 65535U) {
        handle->spawnStatus = -PTY_EINVAL;
        return -PTY_EINVAL;
    }
    if (executable == (const char *)PTY_NULL ||
        !pty_win_path_is_absolute(executable)) {
        handle->spawnStatus = -PTY_EINVAL;
        return -PTY_EINVAL;
    }
    if (cwd == (const char *)PTY_NULL || !pty_win_path_is_absolute(cwd)) {
        handle->spawnStatus = -PTY_EINVAL;
        return -PTY_EINVAL;
    }

    scratch = (PtySpawnScratch *)malloc(sizeof(PtySpawnScratch));
    if (scratch == (PtySpawnScratch *)PTY_NULL) {
        result = -PTY_ENOMEM;
        goto spawn_fail;
    }
    memset(scratch, 0, sizeof(PtySpawnScratch));

    result = pty_prepare_argv(&argv, argvBlock, argvBytes, argc);
    if (result < 0) goto spawn_fail;
    argvStorage = (uint8_t *)argv[0];

    /* Convert executable + cwd to UTF-16. */
    executableWide = pty_win_utf8_to_wide_alloc(executable);
    if (executableWide == (pty_wchar_t *)PTY_NULL) {
        result = -PTY_ENOMEM;
        goto spawn_fail;
    }
    cwdWide = pty_win_utf8_to_wide_alloc(cwd);
    if (cwdWide == (pty_wchar_t *)PTY_NULL) {
        result = -PTY_ENOMEM;
        goto spawn_fail;
    }

    /* Build the wide command line with CommandLineToArgvW-inverse quoting. */
    {
        uint32_t capacity = 2U;
        for (argument = 0U; argument < argc; argument += 1U) {
            int32_t wideCount = pty_win_utf8_to_wide(
                argv[argument],
                (pty_wchar_t *)PTY_NULL,
                0
            );
            if (wideCount <= 0) {
                result = -PTY_EINVAL;
                goto spawn_fail;
            }
            /* Worst case every character escapes to two, plus 2 quotes. */
            capacity += (uint32_t)wideCount * 2U + 4U;
        }
        commandLine = (pty_wchar_t *)malloc((size_t)capacity * sizeof(pty_wchar_t));
        if (commandLine == (pty_wchar_t *)PTY_NULL) {
            result = -PTY_ENOMEM;
            goto spawn_fail;
        }
        cursor = 0U;
        for (argument = 0U; argument < argc; argument += 1U) {
            pty_wchar_t *wideArgument = pty_win_utf8_to_wide_alloc(argv[argument]);
            if (wideArgument == (pty_wchar_t *)PTY_NULL) {
                result = -PTY_ENOMEM;
                goto spawn_fail;
            }
            if (argument > 0U) {
                commandLine[cursor] = (pty_wchar_t)' ';
                cursor += 1U;
            }
            pty_win_append_quoted_argument(commandLine, &cursor, wideArgument);
            free(wideArgument);
        }
        commandLine[cursor] = (pty_wchar_t)'\0';
    }

    /* Build the wide environment block, sorted case-insensitively by name
     * (CreateProcessW requires a sorted Unicode block). An empty handle
     * environment becomes an EMPTY block (one L'\0'), matching pty.c's
     * execve with an empty envp — never NULL, which would inherit the
     * daemon's environment. */
    if (handle->environmentCount == 0U) {
        environmentBlock = (pty_wchar_t *)malloc(sizeof(pty_wchar_t));
        if (environmentBlock == (pty_wchar_t *)PTY_NULL) {
            result = -PTY_ENOMEM;
            goto spawn_fail;
        }
        environmentBlock[0] = (pty_wchar_t)'\0';
    }
    if (handle->environmentCount > 0U) {
        size_t blockCapacity = 1U;
        sortedIndex = (uint32_t *)malloc(
            (size_t)handle->environmentCount * sizeof(uint32_t)
        );
        if (sortedIndex == (uint32_t *)PTY_NULL) {
            result = -PTY_ENOMEM;
            goto spawn_fail;
        }
        for (index = 0U; index < handle->environmentCount; index += 1U)
            sortedIndex[index] = index;
        for (index = 1U; index < handle->environmentCount; index += 1U) {
            uint32_t key = sortedIndex[index];
            uint32_t scan = index;
            while (scan > 0U &&
                   pty_win_ascii_compare_folded(
                       handle->environment[sortedIndex[scan - 1U]].name,
                       handle->environment[key].name
                   ) > 0) {
                sortedIndex[scan] = sortedIndex[scan - 1U];
                scan -= 1U;
            }
            sortedIndex[scan] = key;
        }
        for (index = 0U; index < handle->environmentCount; index += 1U) {
            PtyEnvEntry *entry = &handle->environment[sortedIndex[index]];
            int32_t nameChars = pty_win_utf8_to_wide(
                entry->name,
                (pty_wchar_t *)PTY_NULL,
                0
            );
            int32_t valueChars = pty_win_utf8_to_wide(
                entry->value,
                (pty_wchar_t *)PTY_NULL,
                0
            );
            if (nameChars <= 0 || valueChars <= 0) {
                result = -PTY_EINVAL;
                goto spawn_fail;
            }
            /* name incl NUL + '=' + value incl NUL */
            blockCapacity += (size_t)nameChars + 1U + (size_t)valueChars;
        }
        environmentBlock = (pty_wchar_t *)malloc(
            blockCapacity * sizeof(pty_wchar_t)
        );
        if (environmentBlock == (pty_wchar_t *)PTY_NULL) {
            result = -PTY_ENOMEM;
            goto spawn_fail;
        }
        cursor = 0U;
        for (index = 0U; index < handle->environmentCount; index += 1U) {
            PtyEnvEntry *entry = &handle->environment[sortedIndex[index]];
            int32_t nameChars = pty_win_utf8_to_wide(
                entry->name,
                environmentBlock + cursor,
                (int32_t)(blockCapacity - cursor)
            );
            int32_t valueChars;
            if (nameChars <= 0) {
                result = -PTY_EINVAL;
                goto spawn_fail;
            }
            cursor += (uint32_t)nameChars - 1U;
            environmentBlock[cursor] = (pty_wchar_t)'=';
            cursor += 1U;
            valueChars = pty_win_utf8_to_wide(
                entry->value,
                environmentBlock + cursor,
                (int32_t)(blockCapacity - cursor)
            );
            if (valueChars <= 0) {
                result = -PTY_EINVAL;
                goto spawn_fail;
            }
            cursor += (uint32_t)valueChars - 1U;
            environmentBlock[cursor] = (pty_wchar_t)'\0';
            cursor += 1U;
        }
        environmentBlock[cursor] = (pty_wchar_t)'\0';
        free(sortedIndex);
        sortedIndex = (uint32_t *)PTY_NULL;
    }

    /* Input pipe: the host write end is an OVERLAPPED-capable named pipe —
     * a CreatePipe handle is synchronous, so an OVERLAPPED WriteFile on it
     * would execute synchronously and could stall the daemon when the child
     * stops reading. The child read end is a plain synchronous handle opened
     * by name, marked inheritable so the spawned child can read it.
     * Output pipe: host reads (hOutRead), child writes (hOutWrite); the
     * peek-then-read discipline already keeps host reads non-blocking. */
    {
        /* P3-3 guest finding: TinyCC (bun:ffi cc, win32) mis-emits a
         * function-scope static char array initialized from a string literal
         * in this translation unit — the compiled bytes lose the FIRST
         * character (verified on the win11 guest: "\\.\pipe\..." arrived as
         * ".\pipe\...", CreateNamedPipeW -> ERROR_INVALID_NAME). Char-constant
         * initializers are unaffected in the same TU (verified), so the
         * prefix is spelled out as explicit char constants. Do NOT "simplify"
         * this back into a string literal. */
        static const char kPipePrefix[] = {
            '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\',
            'o', 'p', 'e', 'n', 'l', 'l', 'm', '-', 'p', 't', 'y', '-', '\0'
        };
        uint32_t cursor = 0U;
        size_t prefixIndex;

        pipeAttributes.nLength = sizeof(PtySecurityAttributes);
        pipeAttributes.pad0 = 0U;
        pipeAttributes.lpSecurityDescriptor = PTY_NULL;
        pipeAttributes.bInheritHandle = 0;
        pipeAttributes.pad1 = 0U;

        for (prefixIndex = 0U;
             prefixIndex < sizeof(kPipePrefix) - 1U;
             prefixIndex += 1U) {
            scratch->pipeName[cursor] = (pty_wchar_t)(uint8_t)kPipePrefix[prefixIndex];
            cursor += 1U;
        }
        cursor = pty_win_append_wide_uint(
            scratch->pipeName,
            cursor,
            GetCurrentProcessId()
        );
        scratch->pipeName[cursor] = (pty_wchar_t)'-';
        cursor += 1U;
        cursor = pty_win_append_wide_uint(scratch->pipeName, cursor, ptyNextPipeName);
        ptyNextPipeName += 1U;
        scratch->pipeName[cursor] = (pty_wchar_t)'\0';

        handle->pipeInWrite = CreateNamedPipeW(
            scratch->pipeName,
            PTY_WIN_PIPE_ACCESS_OUTBOUND |
                PTY_WIN_FILE_FLAG_OVERLAPPED |
                PTY_WIN_FILE_FLAG_FIRST_PIPE_INSTANCE,
            PTY_WIN_PIPE_TYPE_BYTE |
                PTY_WIN_PIPE_WAIT |
                PTY_WIN_PIPE_REJECT_REMOTE_CLIENTS,
            1U,
            65536U,
            65536U,
            0U,
            &pipeAttributes
        );
        if (handle->pipeInWrite == PTY_WIN_INVALID_HANDLE_VALUE) {
            handle->pipeInWrite = (pty_handle_t)PTY_NULL;
            result = pty_win_last_error();
            goto spawn_fail;
        }
        pipeAttributes.bInheritHandle = 1;
        pipeInRead = CreateFileW(
            scratch->pipeName,
            PTY_WIN_GENERIC_READ,
            0U,
            &pipeAttributes,
            PTY_WIN_OPEN_EXISTING,
            PTY_WIN_FILE_ATTRIBUTE_NORMAL,
            (pty_handle_t)PTY_NULL
        );
        if (pipeInRead == PTY_WIN_INVALID_HANDLE_VALUE) {
            pipeInRead = (pty_handle_t)PTY_NULL;
            result = pty_win_last_error();
            goto spawn_fail;
        }
    }
    if (CreatePipe(&handle->pipeOutRead, &pipeOutWrite, &pipeAttributes, 0U) ==
        0) {
        result = pty_win_last_error();
        goto spawn_fail;
    }

    consoleSize.x = (pty_i16_t)cols;
    consoleSize.y = (pty_i16_t)rows;
    if (CreatePseudoConsole(
            consoleSize,
            pipeInRead,
            pipeOutWrite,
            0U,
            &handle->pseudoConsole
        ) != 0) {
        result = -PTY_EIO;
        goto spawn_fail;
    }

    /* Attribute list: pseudoconsole only (one attribute). bInheritHandles is
     * FALSE at CreateProcessW below (node-pty: "VERY IMPORTANT") — the child
     * inherits nothing; its stdio comes from the pseudoconsole. The
     * HANDLE_LIST whitelist approach was dropped entirely (P3-3 guest
     * findings below), which also retired the inheritability dance on the
     * pipe ends. */
    SetLastError(0U);
    (void)InitializeProcThreadAttributeList(PTY_NULL, 1U, 0U, &attributeListSize);
    if (attributeListSize == 0U) {
        result = pty_win_last_error();
        goto spawn_fail;
    }
    attributeList = malloc(attributeListSize);
    if (attributeList == PTY_NULL) {
        result = -PTY_ENOMEM;
        goto spawn_fail;
    }
    memset(attributeList, 0, attributeListSize);
    if (InitializeProcThreadAttributeList(attributeList, 1U, 0U, &attributeListSize) == 0) {
        result = pty_win_last_error();
        goto spawn_fail;
    }
    if (UpdateProcThreadAttribute(
            attributeList,
            0U,
            PTY_WIN_PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            handle->pseudoConsole,
            sizeof(handle->pseudoConsole),
            PTY_NULL,
            PTY_NULL
        ) == 0) {
        result = pty_win_last_error();
        goto spawn_fail;
    }
    /* P3-3 guest finding: PROC_THREAD_ATTRIBUTE_HANDLE_LIST was dropped from
     * the attribute list — under the bun:ffi cc (TinyCC) runtime on the win11
     * guest, UpdateProcThreadAttribute(HANDLE_LIST) fails with
     * ERROR_NOT_SUPPORTED even in a minimal repro TU with plain inheritable
     * CreatePipe handles. With bInheritHandles=FALSE the whitelist is moot:
     * the child inherits no handles regardless. */

    memset(&scratch->startupInfo, 0, sizeof(PtyStartupInfoExW));
    /* With EXTENDED_STARTUPINFO_PRESENT the Ex form is used and cb must be
     * sizeof(STARTUPINFOEXW) (112), per Microsoft's ConPTY sample.
     * EXTENDED_STARTUPINFO_PRESENT is a creation flag and appears only in
     * dwCreationFlags below.
     *
     * P3-3 guest finding (win11 build 28000, verified against node-pty's
     * conpty.cc): the pseudoconsole attach SILENTLY no-ops unless dwFlags
     * carries STARTF_USESTDHANDLES with hStdInput/hStdOutput/hStdError left
     * NULL — the NULL std handles get replaced by the pseudoconsole's own.
     * Without the flag the child spawns with inherited std handles instead of
     * attaching to the HPCON (observed: child alive, zero bytes on the output
     * pipe, console output escaping to inherited handles).
     *
     * bInheritHandles is FALSE (node-pty marks this "VERY IMPORTANT"): the
     * child needs no inherited handles at all — the console provides its
     * stdio — so nothing in the daemon's handle table can leak into it. */
    scratch->startupInfo.startupInfo.cb = sizeof(PtyStartupInfoExW);
    scratch->startupInfo.startupInfo.dwFlags = PTY_WIN_STARTF_USESTDHANDLES;
    scratch->startupInfo.lpAttributeList = attributeList;

    memset(&scratch->processInfo, 0, sizeof(PtyProcessInformation));
    if (CreateProcessW(
            executableWide,
            commandLine,
            PTY_NULL,
            PTY_NULL,
            0,
            PTY_WIN_CREATE_UNICODE_ENVIRONMENT |
                PTY_WIN_EXTENDED_STARTUPINFO_PRESENT |
                PTY_WIN_CREATE_SUSPENDED,
            environmentBlock,
            cwdWide,
            &scratch->startupInfo,
            &scratch->processInfo
        ) == 0) {
        result = pty_win_last_error();
        goto spawn_fail;
    }
    DeleteProcThreadAttributeList(attributeList);
    free(attributeList);
    attributeList = PTY_NULL;

    /* Job Object kill-tree: close-on-job-close guarantees containment even
     * if the SIGTERM/SIGKILL escalation is interrupted. */
    jobObject = CreateJobObjectW(PTY_NULL, (const pty_wchar_t *)PTY_NULL);
    if (jobObject == (pty_handle_t)PTY_NULL) {
        result = pty_win_last_error();
        goto spawn_kill_child;
    }
    memset(&scratch->jobLimits, 0, sizeof(PtyJobObjectExtendedLimitInformation));
    scratch->jobLimits.basicLimitInformation.limitFlags =
        PTY_WIN_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (SetInformationJobObject(
            jobObject,
            PTY_WIN_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            &scratch->jobLimits,
            sizeof(PtyJobObjectExtendedLimitInformation)
        ) == 0) {
        result = pty_win_last_error();
        goto spawn_kill_child;
    }
    if (AssignProcessToJobObject(jobObject, scratch->processInfo.hProcess) == 0) {
        result = pty_win_last_error();
        goto spawn_kill_child;
    }
    /* The process remains suspended until containment is established. Resume
     * must retire the one suspend count CreateProcessW added; anything else
     * fails closed through spawn_kill_child. */
    resumeResult = ResumeThread(scratch->processInfo.hThread);
    if (resumeResult != 1U) {
        result = resumeResult == 0xFFFFFFFFUL
            ? pty_win_last_error()
            : -PTY_EIO;
        goto spawn_kill_child;
    }

    /* Host releases its copies of the child-side pipe ends. */
    (void)pty_close_handle(&pipeInRead);
    (void)pty_close_handle(&pipeOutWrite);
    (void)pty_close_handle(&scratch->processInfo.hThread);

    handle->pid = (pid_t)scratch->processInfo.dwProcessId;
    handle->processHandle = scratch->processInfo.hProcess;
    handle->jobHandle = jobObject;
    handle->spawnStatus = 1;
    handle->childReaped = 0;
    handle->childLost = 0;
    handle->waitExitCode = 0;
    handle->waitSignal = 0;
    handle->lastIssuedKillSignal = 0;
    handle->writeInFlight = 0;
    handle->pendingLength = 0U;
    handle->inputBackpressured = 0;
    handle->fatalIoErrno = 0;

    {
        int32_t spawnedPid = (int32_t)scratch->processInfo.dwProcessId;
        free(scratch);
        free(argvStorage);
        free(argv);
        free(commandLine);
        free(executableWide);
        free(cwdWide);
        free(environmentBlock);
        return spawnedPid;
    }

spawn_kill_child:
    /* Fail closed: the child exists but its containment or resume failed.
     * It has not been allowed to run outside its assigned job. */
    (void)TerminateProcess(scratch->processInfo.hProcess, 1U);
    (void)WaitForSingleObject(scratch->processInfo.hProcess, PTY_WIN_INFINITE);
    (void)pty_close_handle(&scratch->processInfo.hThread);
    (void)pty_close_handle(&scratch->processInfo.hProcess);

spawn_fail:
    if (attributeList != PTY_NULL) {
        DeleteProcThreadAttributeList(attributeList);
        free(attributeList);
    }
    (void)pty_close_handle(&pipeInRead);
    (void)pty_close_handle(&pipeOutWrite);
    (void)pty_close_handle(&handle->pipeInWrite);
    (void)pty_close_handle(&handle->pipeOutRead);
    if (handle->pseudoConsole != (pty_handle_t)PTY_NULL) {
        ClosePseudoConsole(handle->pseudoConsole);
        handle->pseudoConsole = (pty_handle_t)PTY_NULL;
    }
    (void)pty_close_handle(&jobObject);
    free(sortedIndex);
    free(environmentBlock);
    free(commandLine);
    free(executableWide);
    free(cwdWide);
    free(argv);
    free(argvStorage);
    free(scratch);
    handle->pid = 0;
    handle->processHandle = (pty_handle_t)PTY_NULL;
    handle->jobHandle = (pty_handle_t)PTY_NULL;
    handle->pipeInWrite = (pty_handle_t)PTY_NULL;
    handle->pipeOutRead = (pty_handle_t)PTY_NULL;
    handle->spawnStatus = result;
    return result;
}

int32_t ptySpawnStatus(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (!handle->spawnStarted) return -PTY_ECHILD;
    return handle->spawnStatus;
}

int32_t ptyPid(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->pid <= 0) return -PTY_ECHILD;
    return (int32_t)handle->pid;
}

int32_t ptyPoll(int32_t handleId, uint32_t interests) {
    PtyHandle *handle = pty_find_handle(handleId);
    uint32_t available = 0U;
    int32_t result = 0;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if ((interests & ~3U) != 0U) return -PTY_EINVAL;
    if (handle->pipeOutRead == (pty_handle_t)PTY_NULL) return -PTY_EBADF;

    if (PeekNamedPipe(
            handle->pipeOutRead,
            PTY_NULL,
            0U,
            PTY_NULL,
            &available,
            PTY_NULL
        ) != 0) {
        if (available > 0U && (interests & 1U) != 0U) result |= 1;
    } else {
        uint32_t errorCode = GetLastError();
        if (errorCode == PTY_WIN_ERROR_BROKEN_PIPE ||
            errorCode == PTY_WIN_ERROR_NO_DATA)
            result |= 4;
        else
            result |= 8;
    }
    if ((interests & 2U) != 0U && handle->pendingLength < PTY_QUEUE_HIGH_WATER)
        result |= 2;
    if ((result & 1) == 0 && handle->processHandle != (pty_handle_t)PTY_NULL) {
        if (WaitForSingleObject(handle->processHandle, 0U) == PTY_WIN_WAIT_OBJECT_0)
            result |= 4;
    }
    return result;
}

int32_t ptyRead(int32_t handleId, uint8_t *buffer, uint32_t capacity) {
    PtyHandle *handle = pty_find_handle(handleId);
    uint32_t available = 0U;
    uint32_t toRead;
    uint32_t got = 0U;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->pipeOutRead == (pty_handle_t)PTY_NULL) return -PTY_EBADF;
    if (capacity > (uint32_t)PTY_INT32_MAX) return -PTY_EINVAL;
    if (capacity > 0U && buffer == (uint8_t *)PTY_NULL) return -PTY_EINVAL;
    if (capacity == 0U) return 0;

    if (PeekNamedPipe(
            handle->pipeOutRead,
            PTY_NULL,
            0U,
            PTY_NULL,
            &available,
            PTY_NULL
        ) == 0) {
        uint32_t errorCode = GetLastError();
        if (errorCode == PTY_WIN_ERROR_BROKEN_PIPE ||
            errorCode == PTY_WIN_ERROR_NO_DATA)
            return 0;
        return -PTY_EIO;
    }
    if (available == 0U) {
        if (handle->processHandle != (pty_handle_t)PTY_NULL &&
            WaitForSingleObject(handle->processHandle, 0U) == PTY_WIN_WAIT_OBJECT_0)
            return 0;
        return -PTY_EAGAIN;
    }
    toRead = available < capacity ? available : capacity;
    if (ReadFile(handle->pipeOutRead, buffer, toRead, &got, PTY_NULL) == 0)
        return -PTY_EIO;
    return (int32_t)got;
}

int32_t ptyWrite(
    int32_t handleId,
    const uint8_t *data,
    uint32_t length,
    uint32_t *acceptedBytes
) {
    PtyHandle *handle;
    const uint8_t *cursor;
    uint32_t remaining;
    int32_t pumpResult;

    if (acceptedBytes == (uint32_t *)PTY_NULL) return -PTY_EINVAL;
    *acceptedBytes = 0U;
    handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->pipeInWrite == (pty_handle_t)PTY_NULL) return -PTY_EBADF;
    if (length > (uint32_t)PTY_INT32_MAX) return -PTY_EINVAL;
    if (length > 0U && data == (const uint8_t *)PTY_NULL) return -PTY_EINVAL;
    if (length == 0U) return 1;
    if (handle->fatalIoErrno > 0) return -handle->fatalIoErrno;

    if (handle->inputBackpressured ||
        handle->pendingLength >= PTY_QUEUE_HIGH_WATER) {
        if (length > PTY_QUEUE_MAX - handle->pendingLength) return 0;
        memcpy(handle->pendingInput + handle->pendingLength, data, (size_t)length);
        handle->pendingLength += length;
        handle->inputBackpressured = 1;
        *acceptedBytes = length;
        return 1;
    }

    pumpResult = pty_win_pump_writes(handle);
    if (pumpResult < 0) return pumpResult;

    /* A second overlapped write may never be issued while one is in flight
     * (pipes are not ordered across concurrent overlapped writes), and new
     * bytes must not jump ahead of the queue — append behind the oldest
     * bytes instead. */
    if (handle->writeInFlight > 0 || handle->pendingLength > 0U) {
        if (length > PTY_QUEUE_MAX - handle->pendingLength) return 0;
        memcpy(handle->pendingInput + handle->pendingLength, data, (size_t)length);
        handle->pendingLength += length;
        *acceptedBytes = length;
        if (handle->pendingLength >= PTY_QUEUE_HIGH_WATER)
            handle->inputBackpressured = 1;
        return 1;
    }

    cursor = data;
    remaining = length;
    while (remaining > 0U) {
        uint32_t chunk = remaining > PTY_WIN_WRITE_CHUNK
            ? PTY_WIN_WRITE_CHUNK
            : remaining;
        uint32_t written = 0U;
        memset(&handle->writeOverlapped, 0, sizeof(PtyOverlapped));
        if (WriteFile(
                handle->pipeInWrite,
                cursor,
                chunk,
                &written,
                &handle->writeOverlapped
            ) != 0) {
            if (written == 0U)
                return pty_record_fatal_io(handle, PTY_EIO);
            cursor += written;
            remaining -= written;
            *acceptedBytes += written;
            continue;
        }
        {
            uint32_t errorCode = GetLastError();
            if (errorCode == PTY_WIN_ERROR_IO_PENDING) {
                handle->writeInFlight = (int32_t)chunk;
                cursor += chunk;
                remaining -= chunk;
                *acceptedBytes += chunk;
                break;
            }
            if (errorCode == PTY_WIN_ERROR_BROKEN_PIPE ||
                errorCode == PTY_WIN_ERROR_NO_DATA ||
                errorCode == PTY_WIN_ERROR_OPERATION_ABORTED ||
                errorCode == PTY_WIN_ERROR_INVALID_HANDLE)
                return pty_record_fatal_io(handle, PTY_EPIPE);
            return pty_record_fatal_io(handle, PTY_EIO);
        }
    }
    if (remaining > 0U) {
        if (remaining > PTY_QUEUE_MAX - handle->pendingLength) return 0;
        memcpy(
            handle->pendingInput + handle->pendingLength,
            cursor,
            (size_t)remaining
        );
        handle->pendingLength += remaining;
        *acceptedBytes += remaining;
        if (handle->pendingLength >= PTY_QUEUE_HIGH_WATER)
            handle->inputBackpressured = 1;
    }
    return 1;
}

int32_t ptyDrain(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    int32_t pumpResult;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->pipeInWrite == (pty_handle_t)PTY_NULL) return -PTY_EBADF;
    if (handle->pendingLength == 0U && handle->writeInFlight == 0) return 1;
    if (handle->fatalIoErrno > 0) return -handle->fatalIoErrno;

    pumpResult = pty_win_pump_writes(handle);
    if (pumpResult < 0) return pumpResult;
    if (handle->pendingLength <= PTY_QUEUE_LOW_WATER)
        handle->inputBackpressured = 0;
    return handle->inputBackpressured ? 0 : 1;
}

int32_t ptyPendingBytes(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    return (int32_t)handle->pendingLength;
}

int32_t ptyBackpressured(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    return handle->inputBackpressured ? 1 : 0;
}

int32_t ptyResize(int32_t handleId, uint32_t cols, uint32_t rows) {
    PtyHandle *handle = pty_find_handle(handleId);
    PtyConsoleSize consoleSize;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->pseudoConsole == (pty_handle_t)PTY_NULL) return -PTY_EBADF;
    if (cols == 0U || cols > 65535U || rows == 0U || rows > 65535U)
        return -PTY_EINVAL;
    consoleSize.x = (pty_i16_t)cols;
    consoleSize.y = (pty_i16_t)rows;
    if (ResizePseudoConsole(handle->pseudoConsole, consoleSize) != 0)
        return -PTY_EIO;
    return 0;
}

int32_t ptyKill(int32_t handleId, int32_t signalNumber, uint32_t targets) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->pid <= 0) return -PTY_ECHILD;
    if (handle->childLost) return -PTY_ESRCH;
    if (handle->childReaped) return -PTY_ESRCH;
    if (signalNumber != PTY_WIN_SIGKILL && signalNumber != PTY_WIN_SIGTERM)
        return -PTY_EINVAL;
    if (targets == 0U || (targets & ~PTY_KILL_ALL_TARGETS) != 0U)
        return -PTY_EINVAL;

    if (signalNumber == PTY_WIN_SIGKILL) {
        if (handle->jobHandle != (pty_handle_t)PTY_NULL) {
            if (TerminateJobObject(handle->jobHandle, PTY_WIN_EXIT_SIGKILL) == 0)
                return pty_win_last_error();
            handle->lastIssuedKillSignal = signalNumber;
            return 0;
        }
        if (TerminateProcess(handle->processHandle, PTY_WIN_EXIT_SIGKILL) == 0)
            return pty_win_last_error();
        handle->lastIssuedKillSignal = signalNumber;
        return 0;
    }

    /* SIGTERM: the root child only; the TS grace escalation (250 ms) issues
     * SIGKILL next, which is the job-tree kill. TerminateProcess succeeds
     * even if the process is already exiting, so there is no reap race. */
    if (TerminateProcess(handle->processHandle, PTY_WIN_EXIT_SIGTERM) == 0)
        return pty_win_last_error();
    handle->lastIssuedKillSignal = signalNumber;
    return 0;
}

int32_t ptyWait(int32_t handleId, int32_t *exitCode, int32_t *signalNumber) {
    PtyHandle *handle = pty_find_handle(handleId);
    uint32_t waitResult;
    uint32_t code = 0U;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (exitCode == (int32_t *)PTY_NULL || signalNumber == (int32_t *)PTY_NULL)
        return -PTY_EINVAL;
    *exitCode = 0;
    *signalNumber = 0;
    if (handle->pid <= 0) return -PTY_ECHILD;
    if (handle->childReaped) {
        *exitCode = handle->waitExitCode;
        *signalNumber = handle->waitSignal;
        return 1;
    }
    if (handle->processHandle == (pty_handle_t)PTY_NULL) return -PTY_ECHILD;

    waitResult = WaitForSingleObject(handle->processHandle, 0U);
    if (waitResult == PTY_WIN_WAIT_TIMEOUT) return 0;
    if (waitResult != PTY_WIN_WAIT_OBJECT_0) return -PTY_EIO;
    if (GetExitCodeProcess(handle->processHandle, &code) == 0) return -PTY_EIO;
    /* pty.c parity: a kill this shim issued reports signalNumber = sig with
     * exitCode = 128 + sig, because TerminateProcess/TerminateJobObject were
     * called with 128 + sig as the exit code. A child that exits 137/143 on
     * its own stays signal 0 — only a recorded kill claims the signal. */
    if (handle->lastIssuedKillSignal != 0 &&
        code == (uint32_t)(128 + handle->lastIssuedKillSignal)) {
        handle->waitSignal = handle->lastIssuedKillSignal;
        handle->waitExitCode = 128 + handle->lastIssuedKillSignal;
    } else {
        handle->waitSignal = 0;
        handle->waitExitCode = (int32_t)code;
    }
    handle->childReaped = 1;
    *exitCode = handle->waitExitCode;
    *signalNumber = handle->waitSignal;
    return 1;
}

int32_t ptyClose(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    uint32_t completedBytes = 0U;
    uint32_t cancelError = 0U;
    uint32_t completionError = 0U;
    int32_t firstError = 0;
    int32_t result;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->writeInFlight > 0) {
#ifdef PTY_TESTING
        if (handle->testCompletionPending > 0U) {
            handle->testCompletionPending -= 1U;
            return -PTY_EBUSY;
        }
#endif
#ifdef PTY_TESTING
        if (handle->testCancelError > 0U) {
            cancelError = handle->testCancelError;
        } else
#endif
        if (CancelIoEx(handle->pipeInWrite, &handle->writeOverlapped) == 0)
            cancelError = GetLastError();
        /* ERROR_NOT_FOUND means no request was found to cancel; completion is
         * still checked below because the I/O may be racing to completion.
         * Other failures leave its lifetime uncertain, so retain the owner. */
        if (cancelError != 0U && cancelError != PTY_WIN_ERROR_NOT_FOUND)
            return -PTY_EIO;
        /* Cancellation is asynchronous. The OVERLAPPED record is embedded in
         * handle, so keep it alive until the operation reaches a terminal
         * completion (including ERROR_OPERATION_ABORTED). */
        if (GetOverlappedResult(
                handle->pipeInWrite,
                &handle->writeOverlapped,
                &completedBytes,
                0
            ) == 0) {
            completionError = GetLastError();
            /* Closing runs on Bun's event-loop thread. An incomplete cancel
             * is retried asynchronously by the owner; never block here. */
            if (completionError == PTY_WIN_ERROR_IO_INCOMPLETE)
                return -PTY_EBUSY;
            if (completionError != PTY_WIN_ERROR_OPERATION_ABORTED &&
                completionError != PTY_WIN_ERROR_BROKEN_PIPE &&
                completionError != PTY_WIN_ERROR_NO_DATA)
                return -PTY_EIO;
        }
        handle->writeInFlight = 0;
    }
    result = pty_close_handle(&handle->pipeInWrite);
    if (result < 0) firstError = result;
    result = pty_close_handle(&handle->pipeOutRead);
    if (result < 0 && firstError == 0) firstError = result;
    if (handle->spawnStatus == 0 && handle->spawnStarted)
        handle->spawnStatus = -PTY_ECANCELED;
    return firstError;
}

int32_t ptyDestroy(int32_t handleId) {
    PtyHandle *handle = ptyHandles;
    PtyHandle *previous = (PtyHandle *)PTY_NULL;
    int32_t closeResult;
    while (handle != (PtyHandle *)PTY_NULL && handle->id != handleId) {
        previous = handle;
        handle = handle->next;
    }
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->pid > 0 && !handle->childReaped && !handle->childLost)
        return -PTY_EBUSY;

    closeResult = ptyClose(handleId);
    /* A failed cancellation/completion check leaves the embedded OVERLAPPED
     * in use. Do not free its owner; ordinary close failures are best-effort
     * once the remaining resources have been retired. */
    if (handle->writeInFlight > 0)
        return closeResult < 0 ? closeResult : -PTY_EIO;
    if (handle->pseudoConsole != (pty_handle_t)PTY_NULL) {
        ClosePseudoConsole(handle->pseudoConsole);
        handle->pseudoConsole = (pty_handle_t)PTY_NULL;
    }
    (void)pty_close_handle(&handle->processHandle);
    /* Closing the job handle applies KILL_ON_JOB_CLOSE: any straggler left
     * between the SIGTERM root kill and the SIGKILL escalation dies here. */
    (void)pty_close_handle(&handle->jobHandle);

    if (previous == (PtyHandle *)PTY_NULL) ptyHandles = handle->next;
    else previous->next = handle->next;
    pty_free_environment(handle);
    free(handle);
    /* The handle has been unlinked and freed. Returning a close error here
     * makes the caller retry ptyDestroy(handleId), which can only produce
     * EBADF and obscures the terminal cleanup result. Close failures are
     * best-effort after all resources are retired. */
    return 0;
}

#ifdef PTY_TESTING
int32_t ptyTestWriteInFlight(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    return handle->writeInFlight > 0 ? 1 : 0;
}

int32_t ptyTestSetCancelError(int32_t handleId, uint32_t errorCode) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    handle->testCancelError = errorCode;
    return 0;
}

int32_t ptyTestSetCompletionPending(int32_t handleId, uint32_t count) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    handle->testCompletionPending = count;
    return 0;
}
#endif
