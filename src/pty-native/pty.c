/*
 * OpenLLM POSIX PTY shim, ABI version 1.
 *
 * This translation unit is deliberately header-free.  The declarations below
 * are the complete libc/kernel ABI surface used by the shim.  The build must
 * select exactly one supported target; an unknown ABI fails at compile time.
 *
 * Supported targets (v2.8): darwin/arm64, darwin/x64, linux/x64, linux/arm64.
 * Darwin is ABI-identical across arm64 and x64 for the surface used here, so
 * one constant set serves both. Linux syscall/fcntl numbers differ between
 * x86_64 and aarch64 and are branched per-architecture below.
 */

#if defined(PTY_DARWIN) && !defined(PTY_LINUX)
#define PTY_TARGET_DARWIN 1
#if !defined(__APPLE__) || !(defined(__aarch64__) || defined(__arm64__) || defined(__x86_64__))
#error "PTY_DARWIN does not match the compiler target (need darwin arm64 or x64)"
#endif
#elif defined(PTY_LINUX) && !defined(PTY_DARWIN)
#define PTY_TARGET_LINUX 1
#if !defined(__linux__) || !(defined(__x86_64__) || defined(__aarch64__))
#error "PTY_LINUX does not match the compiler target (need linux x64 or arm64)"
#endif
#else
#error "pty.c supports only PTY_DARWIN or PTY_LINUX"
#endif

typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
typedef unsigned long size_t;
typedef signed long ssize_t;
typedef int pid_t;

typedef char PtyAssertInt32[(sizeof(int32_t) == 4) ? 1 : -1];
typedef char PtyAssertUint32[(sizeof(uint32_t) == 4) ? 1 : -1];
typedef char PtyAssertUint8[(sizeof(uint8_t) == 1) ? 1 : -1];
typedef char PtyAssertPointer[(sizeof(void *) == 8) ? 1 : -1];

#define PTY_NULL ((void *)0)
#define PTY_INT32_MAX 2147483647
#define PTY_UINT32_MAX 4294967295U
#define PTY_SIZE_MAX ((size_t)-1)

#define PTY_QUEUE_HIGH_WATER 65536U
#define PTY_QUEUE_LOW_WATER 16384U
#define PTY_QUEUE_MAX 262144U

#define PTY_EPERM 1
#define PTY_ENOENT 2
#define PTY_ESRCH 3
#define PTY_EINTR 4
#define PTY_EIO 5
#define PTY_E2BIG 7
#define PTY_EBADF 9
#define PTY_ECHILD 10
#define PTY_ENOMEM 12
#define PTY_EBUSY 16
#define PTY_EINVAL 22
#define PTY_EMFILE 24
#define PTY_EPIPE 32

#define PTY_F_GETFD 1
#define PTY_F_SETFD 2
#define PTY_F_GETFL 3
#define PTY_F_SETFL 4
#define PTY_FD_CLOEXEC 1

#define PTY_POLLIN 0x0001
#define PTY_POLLOUT 0x0004
#define PTY_POLLERR 0x0008
#define PTY_POLLHUP 0x0010
#define PTY_POLLNVAL 0x0020

#define PTY_SIGKILL 9
#define PTY_SIGPIPE 13
#define PTY_WNOHANG 1

#define PTY_KILL_CHILD 1U
#define PTY_KILL_ORIGINAL_GROUP 2U
#define PTY_KILL_FOREGROUND_GROUP 4U
#define PTY_KILL_ALL_TARGETS 7U

#if defined(PTY_TARGET_DARWIN)
typedef unsigned int pty_nfds_t;
#define PTY_F_DUPFD_CLOEXEC 67
#define PTY_O_NONBLOCK 0x00000004
#define PTY_TIOCSCTTY 0x20007461UL
#define PTY_TIOCSWINSZ 0x80087467UL
#define PTY_RLIMIT_NOFILE 8
#define PTY_SIG_SETMASK 3
#define PTY_NSIG 32
#define PTY_EAGAIN 35
#define PTY_ECANCELED 89
#define PTY_ENOSYS 78
#define PTY_ECHILD_NATIVE 10
#define PTY_PROC_PIDLISTFDS 1
#define PTY_PROC_FD_BATCH 64U
#define PTY_F_SETNOSIGPIPE 73
#define PTY_DARWIN_HANDSHAKE_WAIT_READY 0
#define PTY_DARWIN_HANDSHAKE_WRITE_LIST 1
#define PTY_DARWIN_HANDSHAKE_COMPLETE 2
#define PTY_DARWIN_WRITE_BUDGET 65536U
#ifdef PTY_TESTING
#define PTY_TEST_DARWIN_STALL_BEFORE_READY 1
#define PTY_TEST_DARWIN_STALL_DURING_TRANSFER 2
/* P4-6: report testDarwinChildErrno on the error pipe and exit before the
 * ready byte, deterministically reproducing a pre-ready child failure. */
#define PTY_TEST_DARWIN_FAIL_BEFORE_READY 3
#define PTY_SIGSTOP 17
#endif
#elif defined(PTY_TARGET_LINUX)
typedef unsigned long pty_nfds_t;
/* F_DUPFD_CLOEXEC is 1030 on BOTH x86_64 and aarch64 (aarch64 encodes it as
 * __F_DUPFD_CLOEXEC = 1030). O_NONBLOCK / RLIMIT_NOFILE / SIG_SETMASK /
 * EAGAIN / ECANCELED / ENOSYS / ECHILD are arch-identical on Linux. */
#define PTY_F_DUPFD_CLOEXEC 1030
#define PTY_O_NONBLOCK 0x00000800
#define PTY_RLIMIT_NOFILE 7
#define PTY_SIG_SETMASK 2
#define PTY_NSIG 65
#define PTY_EAGAIN 11
#define PTY_ECANCELED 125
#define PTY_ENOSYS 38
#define PTY_ECHILD_NATIVE 10
#if defined(__x86_64__)
/* x86_64: ioctl request = (dir<<30)|(size<<16)|(type<<8)|nr; TIOC* type=0x54. */
#define PTY_TIOCSCTTY 0x0000540eUL
#define PTY_TIOCSWINSZ 0x00005414UL
#define PTY_SYS_PRCTL 157L
#define PTY_SYS_CLOSE_RANGE 436L
#define PTY_SYS_GETDENTS64 217L
#else
/* aarch64: constants VERIFIED against asm-generic/ioctls.h and
 * asm-generic/unistd.h. The aarch64 ABI probe cross-checks them against host
 * headers on every arm64 CI run. */
#define PTY_TIOCSCTTY 0x0000540eUL
#define PTY_TIOCSWINSZ 0x00005414UL
#define PTY_SYS_PRCTL 167L
#define PTY_SYS_CLOSE_RANGE 436L
#define PTY_SYS_GETDENTS64 61L
#endif
/* O_RDONLY / O_CLOEXEC are arch-identical on Linux x86_64 and aarch64. */
#define PTY_O_RDONLY 0
#define PTY_O_CLOEXEC 0x00080000
#define PTY_PR_SET_PDEATHSIG 1UL
#endif

#define PTY_EWOULDBLOCK PTY_EAGAIN

typedef struct PtyWinsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
} PtyWinsize;

typedef struct PtyPollFd {
    int fd;
    short events;
    short revents;
} PtyPollFd;

typedef struct PtyRlimit {
    unsigned long rlim_cur;
    unsigned long rlim_max;
} PtyRlimit;

#if defined(PTY_TARGET_DARWIN)
/* Header-backed by tests/helpers/pty-fd-hole-fixture.c against
 * <sys/proc_info.h>: PROC_PIDLISTFDS=1 and proc_fdinfo={int32,uint32}. */
typedef struct PtyProcFdInfo {
    int32_t proc_fd;
    uint32_t proc_fdtype;
} PtyProcFdInfo;

typedef struct PtyFdListHeader {
    int32_t errorNumber;
    uint32_t count;
} PtyFdListHeader;

typedef char PtyAssertProcFdInfo[(sizeof(PtyProcFdInfo) == 8) ? 1 : -1];
typedef char PtyAssertFdListHeader[(sizeof(PtyFdListHeader) == 8) ? 1 : -1];
#endif

typedef union PtySignalSetStorage {
    unsigned long alignment;
    uint8_t bytes[128];
} PtySignalSetStorage;

extern void *malloc(size_t size);
extern void *calloc(size_t count, size_t size);
extern void *realloc(void *pointer, size_t size);
extern void free(void *pointer);
extern void *memcpy(void *destination, const void *source, size_t length);
extern void *memmove(void *destination, const void *source, size_t length);
extern size_t strlen(const char *value);

extern int openpty(
    int *master,
    int *slave,
    char *name,
    void *termiosValue,
    PtyWinsize *winsizeValue
);
extern pid_t fork(void);
extern pid_t setsid(void);
extern int ioctl(int fd, unsigned long request, ...);
extern int dup2(int oldFd, int newFd);
extern int close(int fd);
extern int fcntl(int fd, int command, ...);
extern int pipe(int fds[2]);
extern ssize_t read(int fd, void *buffer, size_t length);
extern ssize_t write(int fd, const void *buffer, size_t length);
extern int chdir(const char *path);
extern int execve(const char *path, char *const argv[], char *const envp[]);
extern void _exit(int status) __attribute__((noreturn));
extern pid_t getpid(void);
extern pid_t getppid(void);
extern pid_t getpgrp(void);
extern pid_t getpgid(pid_t pid);
extern pid_t tcgetpgrp(int fd);
extern int kill(pid_t pid, int signalNumber);
extern pid_t waitpid(pid_t pid, int *status, int options);
extern int poll(PtyPollFd *fds, pty_nfds_t count, int timeout);
extern int getrlimit(int resource, PtyRlimit *limits);
extern void (*signal(int signalNumber, void (*handler)(int)))(int);
extern int sigemptyset(void *set);
extern int sigprocmask(int how, const void *set, void *oldSet);

#if defined(PTY_TARGET_DARWIN)
extern int *__error(void);
extern int proc_pidinfo(
    int pid,
    int flavor,
    unsigned long arg,
    void *buffer,
    int buffersize
);
#elif defined(PTY_TARGET_LINUX)
extern int *__errno_location(void);
extern long syscall(long number, ...);
#endif

typedef struct PtyEnvEntry {
    char *name;
    char *value;
} PtyEnvEntry;

typedef struct PtyHandle {
    int32_t id;
    int32_t spawnStarted;
    int32_t spawnStatus;
    uint32_t spawnStatusBytes;
    uint8_t spawnStatusBuffer[4];

    pid_t pid;
    pid_t originalPgrp;
    pid_t daemonPgrp;
    int32_t childReaped;
    int32_t childLost;
    int32_t waitExitCode;
    int32_t waitSignal;

    int masterFd;
    int errorReadFd;
    int32_t fatalIoErrno;

#if defined(PTY_TARGET_DARWIN)
    int readyReadFd;
    int descriptorListWriteFd;
    uint8_t *descriptorList;
    uint32_t descriptorListLength;
    uint32_t descriptorListOffset;
    int32_t descriptorHandshakeState;
#endif

    PtyEnvEntry *environment;
    uint32_t environmentCount;
    uint32_t environmentCapacity;

    uint8_t pendingInput[PTY_QUEUE_MAX];
    uint32_t pendingLength;
    int32_t inputBackpressured;

#ifdef PTY_TESTING
    int32_t testWriteCalls;
    int32_t testFailErrno;
    uint32_t testFailCount;
    int32_t testDarwinHandshakeFault;
    int32_t testDarwinChildErrno;
#endif

    struct PtyHandle *next;
} PtyHandle;

typedef struct PtyLaunchData {
    char *executable;
    char *cwd;
    uint8_t *argvStorage;
    char **argv;
    char **envp;
    uint32_t envpCount;
} PtyLaunchData;

static PtyHandle *ptyHandles = (PtyHandle *)PTY_NULL;
static uint32_t ptyNextHandle = 1U;

static int *pty_errno_location(void) {
#if defined(PTY_TARGET_DARWIN)
    return __error();
#else
    return __errno_location();
#endif
}

static int pty_errno(void) {
    return *pty_errno_location();
}

static void pty_set_errno(int errorNumber) {
    *pty_errno_location() = errorNumber;
}

static int32_t pty_negative_errno_or(int fallback) {
    int errorNumber = pty_errno();
    if (errorNumber <= 0) errorNumber = fallback;
    return -errorNumber;
}

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

static int32_t pty_close_one(int *fd) {
    int ownedFd;
    int32_t result = 0;
    if (*fd < 0) return 0;
    ownedFd = *fd;
    *fd = -1;
    if (close(ownedFd) < 0) result = pty_negative_errno_or(PTY_EIO);
    return result;
}

#if defined(PTY_TARGET_DARWIN)
static int32_t pty_darwin_reset_handshake(PtyHandle *handle) {
    int32_t firstError = 0;
    int32_t result;
    result = pty_close_one(&handle->readyReadFd);
    if (result < 0) firstError = result;
    result = pty_close_one(&handle->descriptorListWriteFd);
    if (result < 0 && firstError == 0) firstError = result;
    free(handle->descriptorList);
    handle->descriptorList = (uint8_t *)PTY_NULL;
    handle->descriptorListLength = 0U;
    handle->descriptorListOffset = 0U;
    return firstError;
}
#endif

static int32_t pty_set_cloexec(int fd) {
    int flags = fcntl(fd, PTY_F_GETFD);
    if (flags < 0) return pty_negative_errno_or(PTY_EIO);
    if (fcntl(fd, PTY_F_SETFD, flags | PTY_FD_CLOEXEC) < 0)
        return pty_negative_errno_or(PTY_EIO);
    return 0;
}

static int32_t pty_set_nonblocking(int fd) {
    int flags = fcntl(fd, PTY_F_GETFL);
    if (flags < 0) return pty_negative_errno_or(PTY_EIO);
    if (fcntl(fd, PTY_F_SETFL, flags | PTY_O_NONBLOCK) < 0)
        return pty_negative_errno_or(PTY_EIO);
    return 0;
}

static int32_t pty_prepare_owned_fd(int *fd) {
    int replacement;
    int32_t result;
    if (*fd < 0) return -PTY_EBADF;
    if (*fd < 3) {
        replacement = fcntl(*fd, PTY_F_DUPFD_CLOEXEC, 3);
        if (replacement < 0) return pty_negative_errno_or(PTY_EIO);
        if (close(*fd) < 0) {
            int savedError = pty_errno();
            close(replacement);
            pty_set_errno(savedError);
            return pty_negative_errno_or(PTY_EIO);
        }
        *fd = replacement;
        return 0;
    }
    result = pty_set_cloexec(*fd);
    return result;
}

#if defined(PTY_TARGET_LINUX)
extern int open(const char *path, int flags, ...);

/*
 * Highest fd number open in this process, from /proc/self/fd via the raw
 * getdents64 syscall (no libc directory API, no allocation). Record layout
 * (linux_dirent64): u64 d_ino @0, s64 d_off @8, u16 d_reclen @16,
 * u8 d_type @18, NUL-terminated d_name @19. Returns -1 when unavailable.
 * Called in the post-fork CHILD: open, getdents64 and close are raw
 * syscalls and the buffer is on the stack, so it is async-signal-safe, and
 * the child is single-threaded, so no fd can appear after the scan.
 */
static int32_t pty_highest_open_fd(void) {
    uint8_t buffer[4096];
    int32_t highest = -1;
    int failed = 0;
    int dirFd = open("/proc/self/fd", PTY_O_RDONLY | PTY_O_CLOEXEC);
    if (dirFd < 0) return -1;
    while (!failed) {
        long length = syscall(
            PTY_SYS_GETDENTS64,
            (long)dirFd,
            (long)buffer,
            (long)sizeof(buffer)
        );
        long offset = 0L;
        if (length < 0L) {
            if (pty_errno() == PTY_EINTR) continue;
            failed = 1;
            break;
        }
        if (length == 0L) break;
        while (offset < length) {
            unsigned int recordLength;
            long end;
            long cursor;
            long value = 0L;
            int digits = 0;
            if (offset + 20L > length) {
                failed = 1;
                break;
            }
            recordLength = (unsigned int)buffer[offset + 16L] |
                ((unsigned int)buffer[offset + 17L] << 8);
            end = offset + (long)recordLength;
            if (recordLength < 20U || end > length) {
                failed = 1;
                break;
            }
            cursor = offset + 19L;
            while (
                cursor < end &&
                buffer[cursor] >= (uint8_t)'0' &&
                buffer[cursor] <= (uint8_t)'9' &&
                value <= (long)PTY_INT32_MAX
            ) {
                value = value * 10L + (long)(buffer[cursor] - (uint8_t)'0');
                digits += 1;
                cursor += 1L;
            }
            if (
                digits > 0 && cursor < end && buffer[cursor] == 0U &&
                value <= (long)PTY_INT32_MAX && (int32_t)value > highest
            )
                highest = (int32_t)value;
            offset = end;
        }
    }
    (void)close(dirFd);
    return failed ? -1 : highest;
}

static int32_t pty_descriptor_limit(int32_t *outLimit) {
    PtyRlimit limits;
    if (outLimit == (int32_t *)PTY_NULL) return -PTY_EINVAL;
    if (getrlimit(PTY_RLIMIT_NOFILE, &limits) < 0)
        return pty_negative_errno_or(PTY_EIO);
    if (limits.rlim_cur < 4UL) {
        *outLimit = 4;
        return 0;
    }
    if (limits.rlim_cur > (unsigned long)PTY_INT32_MAX) {
        *outLimit = PTY_INT32_MAX;
    } else {
        *outLimit = (int32_t)limits.rlim_cur;
    }
    return 0;
}
#endif

#if defined(PTY_TARGET_DARWIN)
static int pty_read_exact(int fd, void *buffer, size_t length) {
    uint8_t *cursor = (uint8_t *)buffer;
    size_t offset = 0U;
    while (offset < length) {
        ssize_t amount = read(fd, cursor + offset, length - offset);
        if (amount > 0) {
            offset += (size_t)amount;
            continue;
        }
        if (amount < 0 && pty_errno() == PTY_EINTR) continue;
        if (amount < 0) return pty_errno() > 0 ? pty_errno() : PTY_EIO;
        return PTY_EIO;
    }
    return 0;
}

static int pty_write_exact(int fd, const void *buffer, size_t length) {
    const uint8_t *cursor = (const uint8_t *)buffer;
    size_t offset = 0U;
    while (offset < length) {
        ssize_t amount = write(fd, cursor + offset, length - offset);
        if (amount > 0) {
            offset += (size_t)amount;
            continue;
        }
        if (amount < 0 && pty_errno() == PTY_EINTR) continue;
        if (amount < 0) return pty_errno() > 0 ? pty_errno() : PTY_EIO;
        return PTY_EIO;
    }
    return 0;
}

static int32_t pty_darwin_prepare_descriptor_list(PtyHandle *handle) {
    PtyFdListHeader header;
    uint8_t *list;
    int needed;
    int returned;
    uint32_t total;

    header.errorNumber = 0;
    header.count = 0U;
    needed = proc_pidinfo(
        handle->pid,
        PTY_PROC_PIDLISTFDS,
        0UL,
        PTY_NULL,
        0
    );
    if (needed <= 0) return pty_negative_errno_or(PTY_EIO);
    if (needed % (int)sizeof(PtyProcFdInfo) != 0)
        return -PTY_EIO;
    if (needed > PTY_INT32_MAX - (int)sizeof(PtyFdListHeader))
        return -PTY_E2BIG;

    total = (uint32_t)needed + (uint32_t)sizeof(PtyFdListHeader);
    list = (uint8_t *)malloc((size_t)total);
    if (list == (uint8_t *)PTY_NULL) return -PTY_ENOMEM;
    returned = proc_pidinfo(
        handle->pid,
        PTY_PROC_PIDLISTFDS,
        0UL,
        list + sizeof(PtyFdListHeader),
        needed
    );
    if (returned <= 0) {
        free(list);
        return pty_negative_errno_or(PTY_EIO);
    }
    if (returned > needed ||
        returned % (int)sizeof(PtyProcFdInfo) != 0) {
        free(list);
        return -PTY_EIO;
    }

    header.count = (uint32_t)(returned / (int)sizeof(PtyProcFdInfo));
    memcpy(list, &header, sizeof(header));
    handle->descriptorList = list;
    handle->descriptorListLength =
        (uint32_t)returned + (uint32_t)sizeof(PtyFdListHeader);
    handle->descriptorListOffset = 0U;
    return 0;
}

/*
 * P4-6: a child that dies before the ready byte has already written its
 * errno to the error pipe (fd 3) before _exit(127). Observing EOF on the
 * ready pipe proves the child's write end is closed, so a reported errno
 * is already buffered in the error pipe; recover it once instead of
 * masking the cause behind EIO. The error-pipe read end is nonblocking, so
 * this cannot stall the handshake. Returns -errno, or -PTY_EIO when the
 * child died without reporting anything (e.g. SIGKILLed).
 */
static int32_t pty_darwin_pre_ready_errno(PtyHandle *handle) {
    uint8_t bytes[4];
    ssize_t amount;
    int32_t childError;

    for (;;) {
        amount = read(handle->errorReadFd, bytes, 4U);
        if (amount == 4) {
            memcpy(&childError, bytes, 4U);
            if (childError <= 0) childError = PTY_EIO;
            return -childError;
        }
        if (amount == 0) return -PTY_EIO;
        if (amount > 0) return -PTY_EIO;
        if (pty_errno() == PTY_EINTR) continue;
        if (pty_errno() == PTY_EAGAIN || pty_errno() == PTY_EWOULDBLOCK)
            return -PTY_EIO;
        return -PTY_EIO;
    }
}

/*
 * The Darwin child completes fd-creating setup, sends one ready byte, then
 * blocks on the descriptor-list pipe. ptySpawn returns before that byte is
 * consumed. Each ptySpawnStatus call advances at most one nonblocking pipe
 * operation (and at most 64 KiB of output), so a stopped live child cannot
 * pin the Bun event loop. F_SETNOSIGPIPE is descriptor-local: EPIPE is an
 * explicit startup error without changing the daemon's signal disposition.
 */
static int32_t pty_darwin_advance_handshake(PtyHandle *handle) {
    if (handle->descriptorHandshakeState == PTY_DARWIN_HANDSHAKE_COMPLETE)
        return 1;

    if (handle->descriptorHandshakeState == PTY_DARWIN_HANDSHAKE_WAIT_READY) {
        uint8_t readyByte = 0U;
        ssize_t amount = read(handle->readyReadFd, &readyByte, 1U);
        int32_t result;
        if (amount < 0) {
            int errorNumber = pty_errno();
            if (errorNumber == PTY_EINTR ||
                errorNumber == PTY_EAGAIN ||
                errorNumber == PTY_EWOULDBLOCK)
                return 0;
            return errorNumber > 0 ? -errorNumber : -PTY_EIO;
        }
        if (amount == 0) return pty_darwin_pre_ready_errno(handle);
        if (readyByte != 1U) return -PTY_EIO;
        result = pty_close_one(&handle->readyReadFd);
        if (result < 0) return result;
        result = pty_darwin_prepare_descriptor_list(handle);
        if (result < 0) return result;
        handle->descriptorHandshakeState = PTY_DARWIN_HANDSHAKE_WRITE_LIST;
        return 0;
    }

    if (handle->descriptorHandshakeState == PTY_DARWIN_HANDSHAKE_WRITE_LIST) {
        uint32_t remaining =
            handle->descriptorListLength - handle->descriptorListOffset;
        uint32_t amountToWrite = remaining < PTY_DARWIN_WRITE_BUDGET
            ? remaining
            : PTY_DARWIN_WRITE_BUDGET;
        ssize_t amount = write(
            handle->descriptorListWriteFd,
            handle->descriptorList + handle->descriptorListOffset,
            (size_t)amountToWrite
        );
        if (amount > 0) {
            int32_t result;
            handle->descriptorListOffset += (uint32_t)amount;
            if (handle->descriptorListOffset < handle->descriptorListLength)
                return 0;
            result = pty_darwin_reset_handshake(handle);
            if (result < 0) return result;
            handle->descriptorHandshakeState = PTY_DARWIN_HANDSHAKE_COMPLETE;
            return 1;
        }
        if (amount < 0) {
            int errorNumber = pty_errno();
            if (errorNumber == PTY_EINTR ||
                errorNumber == PTY_EAGAIN ||
                errorNumber == PTY_EWOULDBLOCK)
                return 0;
            return errorNumber > 0 ? -errorNumber : -PTY_EIO;
        }
        return -PTY_EIO;
    }

    return -PTY_EIO;
}
#endif

static void pty_launch_data_init(PtyLaunchData *launch) {
    launch->executable = (char *)PTY_NULL;
    launch->cwd = (char *)PTY_NULL;
    launch->argvStorage = (uint8_t *)PTY_NULL;
    launch->argv = (char **)PTY_NULL;
    launch->envp = (char **)PTY_NULL;
    launch->envpCount = 0U;
}

static void pty_launch_data_free(PtyLaunchData *launch) {
    uint32_t index;
    free(launch->executable);
    free(launch->cwd);
    free(launch->argvStorage);
    free(launch->argv);
    if (launch->envp != (char **)PTY_NULL) {
        for (index = 0U; index < launch->envpCount; index += 1U)
            free(launch->envp[index]);
    }
    free(launch->envp);
    pty_launch_data_init(launch);
}

static int32_t pty_prepare_argv(
    PtyLaunchData *launch,
    const uint8_t *argvBlock,
    uint32_t argvBytes,
    uint32_t argc
) {
    uint32_t index;
    uint32_t offset = 0U;
    uint32_t argument = 0U;

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

    launch->argvStorage = (uint8_t *)malloc((size_t)argvBytes);
    if (launch->argvStorage == (uint8_t *)PTY_NULL) return -PTY_ENOMEM;
    memcpy(launch->argvStorage, argvBlock, (size_t)argvBytes);

    launch->argv = (char **)calloc((size_t)argc + 1U, sizeof(char *));
    if (launch->argv == (char **)PTY_NULL) return -PTY_ENOMEM;
    for (argument = 0U; argument < argc; argument += 1U) {
        launch->argv[argument] = (char *)(launch->argvStorage + offset);
        while (offset < argvBytes && launch->argvStorage[offset] != 0U) offset += 1U;
        if (offset >= argvBytes) return -PTY_EINVAL;
        offset += 1U;
    }
    if (offset != argvBytes) return -PTY_EINVAL;
    launch->argv[argc] = (char *)PTY_NULL;
    return 0;
}

static int32_t pty_prepare_env(PtyHandle *handle, PtyLaunchData *launch) {
    uint32_t index;
    if ((size_t)handle->environmentCount + 1U > PTY_SIZE_MAX / sizeof(char *))
        return -PTY_E2BIG;
    launch->envp = (char **)calloc(
        (size_t)handle->environmentCount + 1U,
        sizeof(char *)
    );
    if (launch->envp == (char **)PTY_NULL) return -PTY_ENOMEM;

    for (index = 0U; index < handle->environmentCount; index += 1U) {
        size_t nameLength = strlen(handle->environment[index].name);
        size_t valueLength = strlen(handle->environment[index].value);
        size_t total;
        char *entry;
        if (valueLength > PTY_SIZE_MAX - 2U ||
            nameLength > PTY_SIZE_MAX - valueLength - 2U)
            return -PTY_E2BIG;
        total = nameLength + valueLength + 2U;
        entry = (char *)malloc(total);
        if (entry == (char *)PTY_NULL) return -PTY_ENOMEM;
        memcpy(entry, handle->environment[index].name, nameLength);
        entry[nameLength] = '=';
        memcpy(entry + nameLength + 1U, handle->environment[index].value, valueLength);
        entry[total - 1U] = '\0';
        launch->envp[index] = entry;
        launch->envpCount += 1U;
    }
    launch->envp[handle->environmentCount] = (char *)PTY_NULL;
    return 0;
}

static int32_t pty_prepare_launch(
    PtyHandle *handle,
    PtyLaunchData *launch,
    const char *executable,
    const char *cwd,
    const uint8_t *argvBlock,
    uint32_t argvBytes,
    uint32_t argc
) {
    int32_t result;
    if (executable == (const char *)PTY_NULL || executable[0] != '/') return -PTY_EINVAL;
    if (cwd == (const char *)PTY_NULL || cwd[0] != '/') return -PTY_EINVAL;

    launch->executable = pty_copy_string(executable);
    if (launch->executable == (char *)PTY_NULL) return -PTY_ENOMEM;
    launch->cwd = pty_copy_string(cwd);
    if (launch->cwd == (char *)PTY_NULL) return -PTY_ENOMEM;

    result = pty_prepare_argv(launch, argvBlock, argvBytes, argc);
    if (result < 0) return result;
    result = pty_prepare_env(handle, launch);
    if (result < 0) return result;
    return 0;
}

static void pty_child_report_and_exit_fd(int errorFd, int errorNumber)
    __attribute__((noreturn));

static void pty_child_report_and_exit_fd(int errorFd, int errorNumber) {
    /* Native byte order through a union: no libc call (memcpy) between fork
     * and exec, where only async-signal-safe operations are allowed. */
    union {
        int value;
        uint8_t bytes[4];
    } encoded;
    uint8_t *bytes = encoded.bytes;
    size_t offset = 0U;
    if (errorNumber <= 0) errorNumber = PTY_EIO;
    encoded.value = errorNumber;
    while (offset < 4U) {
        ssize_t written = write(errorFd, bytes + offset, 4U - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && pty_errno() == PTY_EINTR) continue;
        break;
    }
    _exit(127);
}

#if defined(PTY_TARGET_LINUX)
static int pty_child_close_descriptors(int32_t closeLimit) {
    int fd;
    int32_t highest;
#if !(defined(PTY_TESTING) && defined(PTY_TEST_FORCE_CLOSE_FALLBACK))
    if (syscall(PTY_SYS_CLOSE_RANGE, 4U, PTY_UINT32_MAX, 0U) == 0L) return 0;
#endif
    /*
     * Kernels before 5.9 lack close_range. Closing one fd at a time up to
     * RLIMIT_NOFILE is unbounded in practice (Bun raises it to the hard
     * maximum, often 2^19-2^20 and far more in some containers), so stop at
     * the highest fd actually open, scanned here in the single-threaded child
     * where nothing can open a new fd afterwards. If the scan fails, the
     * rlimit bound stays.
     */
    highest = pty_highest_open_fd();
    if (highest >= 0 && highest + 1 < closeLimit) closeLimit = highest + 1;
    for (fd = 4; fd < closeLimit; fd += 1) {
        if (close(fd) < 0 && pty_errno() != PTY_EBADF) return pty_errno();
    }
    return 0;
}
#else
static int pty_child_close_descriptors(
    int listReadFd,
    uint32_t count,
    int32_t testHandshakeFault
) {
    PtyProcFdInfo entries[PTY_PROC_FD_BATCH];
    uint32_t remaining = count;
    int firstError = 0;
    while (remaining > 0U) {
        uint32_t batch = remaining < PTY_PROC_FD_BATCH
            ? remaining
            : PTY_PROC_FD_BATCH;
        uint32_t index;
        int result = pty_read_exact(
            listReadFd,
            entries,
            (size_t)batch * sizeof(PtyProcFdInfo)
        );
        if (result != 0) return result;
        for (index = 0U; index < batch; index += 1U) {
            int fd = entries[index].proc_fd;
            if (fd < 4 || fd == listReadFd) continue;
            if (close(fd) < 0 && pty_errno() != PTY_EBADF && firstError == 0)
                firstError = pty_errno() > 0 ? pty_errno() : PTY_EIO;
        }
        remaining -= batch;
#ifdef PTY_TESTING
        if (testHandshakeFault == PTY_TEST_DARWIN_STALL_DURING_TRANSFER &&
            remaining > 0U)
            (void)kill(getpid(), PTY_SIGSTOP);
#else
        (void)testHandshakeFault;
#endif
    }
    if (close(listReadFd) < 0 && pty_errno() != PTY_EBADF && firstError == 0)
        firstError = pty_errno() > 0 ? pty_errno() : PTY_EIO;
    return firstError;
}
#endif

static void pty_child_exec(
    int slaveFd,
    int errorWriteFd,
    int32_t closeLimit,
    pid_t parentPid,
    const PtyLaunchData *launch,
    int descriptorListReadFd,
    int descriptorListWriteFd,
    int readyReadFd,
    int readyWriteFd,
    int32_t testHandshakeFault,
    int32_t testChildErrno
) {
    int descriptor;
    int errorNumber;
    PtySignalSetStorage emptyMask;
    void (*oldHandler)(int);
#if defined(PTY_TARGET_DARWIN)
    PtyFdListHeader fdListHeader;
    uint8_t readyByte = 1U;
    (void)closeLimit;
#endif

    /*
     * Reset every signal disposition to default FIRST. Ignored signals survive
     * execve: a daemon started with SIGHUP/SIGTERM ignored (nohup, some service
     * managers) would otherwise hand that to every PTY shell, and closing a
     * session could no longer hang up its processes. Caught handlers are reset
     * by execve anyway, but resetting here also keeps the parent's handlers
     * from running in the child before exec. SIGKILL/SIGSTOP (and signals the
     * libc reserves) fail with EINVAL — harmless, so results are ignored.
     */
    for (descriptor = 1; descriptor < PTY_NSIG; descriptor += 1)
        (void)signal(descriptor, (void (*)(int))PTY_NULL);

    /*
     * Establish the reserved status descriptor before any fallible setup step.
     * If the slave happened to occupy fd 3, move it first so failures can still
     * be reconciled by the parent through the error pipe.
     */
    if (slaveFd == 3) {
        int movedSlave = fcntl(slaveFd, PTY_F_DUPFD_CLOEXEC, 4);
        if (movedSlave < 0)
            pty_child_report_and_exit_fd(errorWriteFd, pty_errno());
        slaveFd = movedSlave;
    }
    if (errorWriteFd != 3) {
        if (dup2(errorWriteFd, 3) < 0)
            pty_child_report_and_exit_fd(errorWriteFd, pty_errno());
    }
    if (fcntl(3, PTY_F_SETFD, PTY_FD_CLOEXEC) < 0)
        pty_child_report_and_exit_fd(3, pty_errno());

#if defined(PTY_TARGET_DARWIN)
    if (close(descriptorListWriteFd) < 0 && pty_errno() != PTY_EBADF)
        pty_child_report_and_exit_fd(3, pty_errno());
    if (close(readyReadFd) < 0 && pty_errno() != PTY_EBADF)
        pty_child_report_and_exit_fd(3, pty_errno());
#else
    (void)descriptorListReadFd;
    (void)descriptorListWriteFd;
    (void)readyReadFd;
    (void)readyWriteFd;
    (void)testHandshakeFault;
    (void)testChildErrno;
#endif

    if (setsid() < 0) pty_child_report_and_exit_fd(3, pty_errno());
    if (ioctl(slaveFd, PTY_TIOCSCTTY, 0) < 0)
        pty_child_report_and_exit_fd(3, pty_errno());

    for (descriptor = 0; descriptor <= 2; descriptor += 1) {
        if (dup2(slaveFd, descriptor) < 0)
            pty_child_report_and_exit_fd(3, pty_errno());
    }

    oldHandler = signal(PTY_SIGPIPE, (void (*)(int))PTY_NULL);
    if (oldHandler == (void (*)(int))-1)
        pty_child_report_and_exit_fd(3, pty_errno());
    if (sigemptyset((void *)&emptyMask) < 0)
        pty_child_report_and_exit_fd(3, pty_errno());
    if (sigprocmask(PTY_SIG_SETMASK, (const void *)&emptyMask, PTY_NULL) < 0)
        pty_child_report_and_exit_fd(3, pty_errno());

#if defined(PTY_TARGET_LINUX)
    if (syscall(
            PTY_SYS_PRCTL,
            PTY_PR_SET_PDEATHSIG,
            (unsigned long)PTY_SIGKILL,
            0UL,
            0UL,
            0UL
        ) < 0L)
        pty_child_report_and_exit_fd(3, pty_errno());
    if (getppid() != parentPid) pty_child_report_and_exit_fd(3, PTY_ECHILD);
#else
    (void)parentPid;
#endif

#if defined(PTY_TARGET_DARWIN)
#ifdef PTY_TESTING
    if (testHandshakeFault == PTY_TEST_DARWIN_STALL_BEFORE_READY)
        (void)kill(getpid(), PTY_SIGSTOP);
    if (testHandshakeFault == PTY_TEST_DARWIN_FAIL_BEFORE_READY)
        pty_child_report_and_exit_fd(3, testChildErrno);
#else
    (void)testChildErrno;
#endif
    errorNumber = pty_write_exact(readyWriteFd, &readyByte, 1U);
    if (errorNumber != 0)
        pty_child_report_and_exit_fd(3, errorNumber);
    if (close(readyWriteFd) < 0 && pty_errno() != PTY_EBADF)
        pty_child_report_and_exit_fd(3, pty_errno());
    errorNumber = pty_read_exact(
        descriptorListReadFd,
        &fdListHeader,
        sizeof(fdListHeader)
    );
    if (errorNumber != 0)
        pty_child_report_and_exit_fd(3, errorNumber);
    if (fdListHeader.errorNumber != 0)
        pty_child_report_and_exit_fd(3, fdListHeader.errorNumber);
    errorNumber = pty_child_close_descriptors(
        descriptorListReadFd,
        fdListHeader.count,
        testHandshakeFault
    );
#else
    errorNumber = pty_child_close_descriptors(closeLimit);
#endif
    if (errorNumber != 0) pty_child_report_and_exit_fd(3, errorNumber);

    if (chdir(launch->cwd) < 0) pty_child_report_and_exit_fd(3, pty_errno());
    execve(launch->executable, launch->argv, launch->envp);
    pty_child_report_and_exit_fd(3, pty_errno());
}

static ssize_t pty_underlying_write(PtyHandle *handle, const void *data, size_t length) {
#ifdef PTY_TESTING
    if (handle->testWriteCalls < PTY_INT32_MAX) handle->testWriteCalls += 1;
    if (handle->testFailCount > 0U) {
        int injectedError = handle->testFailErrno;
        handle->testFailCount -= 1U;
        if (injectedError == 0) return 0;
        pty_set_errno(injectedError);
        return -1;
    }
#endif
    return write(handle->masterFd, data, length);
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

static int32_t pty_record_fatal_io(PtyHandle *handle, int fallback) {
    int errorNumber = pty_errno();
    if (errorNumber <= 0) errorNumber = fallback;
    handle->fatalIoErrno = errorNumber;
    return -errorNumber;
}

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
    handle->masterFd = -1;
    handle->errorReadFd = -1;
#if defined(PTY_TARGET_DARWIN)
    handle->readyReadFd = -1;
    handle->descriptorListWriteFd = -1;
    handle->descriptorHandshakeState = PTY_DARWIN_HANDSHAKE_WAIT_READY;
#endif
    handle->daemonPgrp = getpgrp();
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
            int same = 1;
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
    PtyLaunchData launch;
    PtyWinsize winsizeValue;
    int masterFd = -1;
    int slaveFd = -1;
    int errorPipe[2] = {-1, -1};
    int32_t closeLimit = 4;
    int32_t result;
    pid_t childPid;
    pid_t parentPid;
    int32_t testHandshakeFault = 0;
    int32_t testChildErrno = 0;
#if defined(PTY_TARGET_DARWIN)
    int descriptorListPipe[2] = {-1, -1};
    int readyPipe[2] = {-1, -1};
#endif

    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->spawnStarted) return -PTY_EBUSY;
    handle->spawnStarted = 1;
#ifdef PTY_TESTING
    testHandshakeFault = handle->testDarwinHandshakeFault;
    testChildErrno = handle->testDarwinChildErrno;
#endif
    if (cols == 0U || cols > 65535U || rows == 0U || rows > 65535U) {
        handle->spawnStatus = -PTY_EINVAL;
        return -PTY_EINVAL;
    }

    pty_launch_data_init(&launch);
    result = pty_prepare_launch(
        handle,
        &launch,
        executable,
        cwd,
        argvBlock,
        argvBytes,
        argc
    );
    if (result < 0) goto fail_before_fork;
#if defined(PTY_TARGET_LINUX)
    /* Linux: close_range(4, UINT32_MAX) is a single syscall — the rlimit bound
     * is fine and correct. */
    result = pty_descriptor_limit(&closeLimit);
    if (result < 0) goto fail_before_fork;
#endif

    winsizeValue.ws_row = (unsigned short)rows;
    winsizeValue.ws_col = (unsigned short)cols;
    winsizeValue.ws_xpixel = 0U;
    winsizeValue.ws_ypixel = 0U;
    if (openpty(&masterFd, &slaveFd, (char *)PTY_NULL, PTY_NULL, &winsizeValue) < 0) {
        result = pty_negative_errno_or(PTY_EIO);
        goto fail_before_fork;
    }
    result = pty_prepare_owned_fd(&masterFd);
    if (result < 0) goto fail_before_fork;
    result = pty_prepare_owned_fd(&slaveFd);
    if (result < 0) goto fail_before_fork;
    result = pty_set_nonblocking(masterFd);
    if (result < 0) goto fail_before_fork;

    if (pipe(errorPipe) < 0) {
        result = pty_negative_errno_or(PTY_EIO);
        goto fail_before_fork;
    }
    result = pty_prepare_owned_fd(&errorPipe[0]);
    if (result < 0) goto fail_before_fork;
    result = pty_prepare_owned_fd(&errorPipe[1]);
    if (result < 0) goto fail_before_fork;
    result = pty_set_nonblocking(errorPipe[0]);
    if (result < 0) goto fail_before_fork;

#if defined(PTY_TARGET_DARWIN)
    if (pipe(descriptorListPipe) < 0) {
        result = pty_negative_errno_or(PTY_EIO);
        goto fail_before_fork;
    }
    result = pty_prepare_owned_fd(&descriptorListPipe[0]);
    if (result < 0) goto fail_before_fork;
    result = pty_prepare_owned_fd(&descriptorListPipe[1]);
    if (result < 0) goto fail_before_fork;
    result = pty_set_nonblocking(descriptorListPipe[1]);
    if (result < 0) goto fail_before_fork;
    if (fcntl(descriptorListPipe[1], PTY_F_SETNOSIGPIPE, 1) < 0) {
        result = pty_negative_errno_or(PTY_EIO);
        goto fail_before_fork;
    }

    if (pipe(readyPipe) < 0) {
        result = pty_negative_errno_or(PTY_EIO);
        goto fail_before_fork;
    }
    result = pty_prepare_owned_fd(&readyPipe[0]);
    if (result < 0) goto fail_before_fork;
    result = pty_prepare_owned_fd(&readyPipe[1]);
    if (result < 0) goto fail_before_fork;
    result = pty_set_nonblocking(readyPipe[0]);
    if (result < 0) goto fail_before_fork;
#endif

    parentPid = getpid();
    childPid = fork();
    if (childPid < 0) {
        result = pty_negative_errno_or(PTY_EIO);
        goto fail_before_fork;
    }
    if (childPid == 0) {
#if defined(PTY_TARGET_DARWIN)
        pty_child_exec(
            slaveFd,
            errorPipe[1],
            closeLimit,
            parentPid,
            &launch,
            descriptorListPipe[0],
            descriptorListPipe[1],
            readyPipe[0],
            readyPipe[1],
            testHandshakeFault,
            testChildErrno
        );
#else
        pty_child_exec(
            slaveFd,
            errorPipe[1],
            closeLimit,
            parentPid,
            &launch,
            -1,
            -1,
            -1,
            -1,
            testHandshakeFault,
            testChildErrno
        );
#endif
        _exit(127);
    }

    close(slaveFd);
    slaveFd = -1;
    close(errorPipe[1]);
    errorPipe[1] = -1;
#if defined(PTY_TARGET_DARWIN)
    close(descriptorListPipe[0]);
    descriptorListPipe[0] = -1;
    close(readyPipe[1]);
    readyPipe[1] = -1;
#endif
    handle->pid = childPid;
    handle->originalPgrp = childPid;
    handle->masterFd = masterFd;
    handle->errorReadFd = errorPipe[0];
    masterFd = -1;
    errorPipe[0] = -1;
#if defined(PTY_TARGET_DARWIN)
    handle->readyReadFd = readyPipe[0];
    handle->descriptorListWriteFd = descriptorListPipe[1];
    handle->descriptorHandshakeState = PTY_DARWIN_HANDSHAKE_WAIT_READY;
    readyPipe[0] = -1;
    descriptorListPipe[1] = -1;
#endif
    pty_launch_data_free(&launch);
    return (int32_t)childPid;

fail_before_fork:
    if (masterFd >= 0) close(masterFd);
    if (slaveFd >= 0) close(slaveFd);
    if (errorPipe[0] >= 0) close(errorPipe[0]);
    if (errorPipe[1] >= 0) close(errorPipe[1]);
#if defined(PTY_TARGET_DARWIN)
    if (descriptorListPipe[0] >= 0) close(descriptorListPipe[0]);
    if (descriptorListPipe[1] >= 0) close(descriptorListPipe[1]);
    if (readyPipe[0] >= 0) close(readyPipe[0]);
    if (readyPipe[1] >= 0) close(readyPipe[1]);
#endif
    pty_launch_data_free(&launch);
    handle->spawnStatus = result;
    return result;
}

int32_t ptySpawnStatus(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (!handle->spawnStarted) return -PTY_ECHILD;
    if (handle->spawnStatus != 0) return handle->spawnStatus;
    if (handle->pid <= 0) return -PTY_ECHILD;
    if (handle->errorReadFd < 0) {
        handle->spawnStatus = -PTY_ECANCELED;
        return handle->spawnStatus;
    }

#if defined(PTY_TARGET_DARWIN)
    if (handle->descriptorHandshakeState != PTY_DARWIN_HANDSHAKE_COMPLETE) {
        int32_t handshake = pty_darwin_advance_handshake(handle);
        if (handshake < 0) {
            handle->spawnStatus = handshake;
            (void)pty_darwin_reset_handshake(handle);
            (void)pty_close_one(&handle->errorReadFd);
            return handle->spawnStatus;
        }
        if (handshake == 0) return 0;
    }
#endif

    for (;;) {
        ssize_t amount = read(
            handle->errorReadFd,
            handle->spawnStatusBuffer + handle->spawnStatusBytes,
            (size_t)(4U - handle->spawnStatusBytes)
        );
        if (amount > 0) {
            int32_t childError;
            handle->spawnStatusBytes += (uint32_t)amount;
            if (handle->spawnStatusBytes < 4U) continue;
            memcpy(&childError, handle->spawnStatusBuffer, 4U);
            if (childError <= 0) childError = PTY_EIO;
            handle->spawnStatus = -childError;
            pty_close_one(&handle->errorReadFd);
            return handle->spawnStatus;
        }
        if (amount == 0) {
            handle->spawnStatus = handle->spawnStatusBytes == 0U ? 1 : -PTY_EIO;
            pty_close_one(&handle->errorReadFd);
            return handle->spawnStatus;
        }
        if (pty_errno() == PTY_EINTR) continue;
        if (pty_errno() == PTY_EAGAIN || pty_errno() == PTY_EWOULDBLOCK) return 0;
        handle->spawnStatus = pty_negative_errno_or(PTY_EIO);
        pty_close_one(&handle->errorReadFd);
        return handle->spawnStatus;
    }
}

int32_t ptyPid(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->pid <= 0) return -PTY_ECHILD;
    return (int32_t)handle->pid;
}

int32_t ptyPoll(int32_t handleId, uint32_t interests) {
    PtyHandle *handle = pty_find_handle(handleId);
    PtyPollFd descriptor;
    int pollResult;
    int32_t result = 0;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if ((interests & ~3U) != 0U) return -PTY_EINVAL;
    if (handle->masterFd < 0) return -PTY_EBADF;
    descriptor.fd = handle->masterFd;
    descriptor.events = 0;
    descriptor.revents = 0;
    if ((interests & 1U) != 0U) descriptor.events |= PTY_POLLIN;
    if ((interests & 2U) != 0U) descriptor.events |= PTY_POLLOUT;
    pollResult = poll(&descriptor, (pty_nfds_t)1U, 0);
    if (pollResult < 0) return pty_negative_errno_or(PTY_EIO);
    if ((descriptor.revents & PTY_POLLIN) != 0) result |= 1;
    if ((descriptor.revents & PTY_POLLOUT) != 0) result |= 2;
    if ((descriptor.revents & PTY_POLLHUP) != 0) result |= 4;
    if ((descriptor.revents & (PTY_POLLERR | PTY_POLLNVAL)) != 0) result |= 8;
    return result;
}

int32_t ptyRead(int32_t handleId, uint8_t *buffer, uint32_t capacity) {
    PtyHandle *handle = pty_find_handle(handleId);
    ssize_t amount;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->masterFd < 0) return -PTY_EBADF;
    if (capacity > (uint32_t)PTY_INT32_MAX) return -PTY_EINVAL;
    if (capacity > 0U && buffer == (uint8_t *)PTY_NULL) return -PTY_EINVAL;
    if (capacity == 0U) return 0;
    amount = read(handle->masterFd, buffer, (size_t)capacity);
    if (amount >= 0) return (int32_t)amount;
    if (pty_errno() == PTY_EIO) return 0;
    return pty_negative_errno_or(PTY_EIO);
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

    if (acceptedBytes == (uint32_t *)PTY_NULL) return -PTY_EINVAL;
    *acceptedBytes = 0U;
    handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->masterFd < 0) return -PTY_EBADF;
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

    if (handle->pendingLength > 0U) {
        ssize_t amount = pty_underlying_write(
            handle,
            handle->pendingInput,
            (size_t)handle->pendingLength
        );
        if (amount > 0) {
            pty_remove_pending_prefix(handle, (uint32_t)amount);
        } else if (amount < 0 &&
                   pty_errno() != PTY_EINTR &&
                   pty_errno() != PTY_EAGAIN &&
                   pty_errno() != PTY_EWOULDBLOCK) {
            return pty_record_fatal_io(handle, PTY_EIO);
        }
        if (handle->pendingLength > 0U) {
            if (length > PTY_QUEUE_MAX - handle->pendingLength) return 0;
            memcpy(handle->pendingInput + handle->pendingLength, data, (size_t)length);
            handle->pendingLength += length;
            if (handle->pendingLength >= PTY_QUEUE_HIGH_WATER)
                handle->inputBackpressured = 1;
            *acceptedBytes = length;
            return 1;
        }
    }

    cursor = data;
    remaining = length;
    while (remaining > 0U) {
        ssize_t amount = pty_underlying_write(handle, cursor, (size_t)remaining);
        if (amount > 0) {
            uint32_t delivered = (uint32_t)amount;
            cursor += delivered;
            remaining -= delivered;
            *acceptedBytes += delivered;
            continue;
        }
        if (amount < 0 &&
            (pty_errno() == PTY_EINTR ||
             pty_errno() == PTY_EAGAIN ||
             pty_errno() == PTY_EWOULDBLOCK)) {
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
            return 1;
        }
        if (amount == 0) pty_set_errno(PTY_EIO);
        return pty_record_fatal_io(handle, PTY_EIO);
    }
    return 1;
}

int32_t ptyDrain(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->masterFd < 0) return -PTY_EBADF;
    if (handle->pendingLength == 0U) return 1;
    if (handle->fatalIoErrno > 0) return -handle->fatalIoErrno;

    while (handle->pendingLength > 0U) {
        ssize_t amount = pty_underlying_write(
            handle,
            handle->pendingInput,
            (size_t)handle->pendingLength
        );
        if (amount > 0) {
            pty_remove_pending_prefix(handle, (uint32_t)amount);
            continue;
        }
        if (amount < 0 &&
            (pty_errno() == PTY_EINTR ||
             pty_errno() == PTY_EAGAIN ||
             pty_errno() == PTY_EWOULDBLOCK))
            break;
        if (amount == 0) pty_set_errno(PTY_EIO);
        return pty_record_fatal_io(handle, PTY_EIO);
    }
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
    PtyWinsize winsizeValue;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->masterFd < 0) return -PTY_EBADF;
    if (cols == 0U || cols > 65535U || rows == 0U || rows > 65535U)
        return -PTY_EINVAL;
    winsizeValue.ws_row = (unsigned short)rows;
    winsizeValue.ws_col = (unsigned short)cols;
    winsizeValue.ws_xpixel = 0U;
    winsizeValue.ws_ypixel = 0U;
    if (ioctl(handle->masterFd, PTY_TIOCSWINSZ, &winsizeValue) < 0)
        return pty_negative_errno_or(PTY_EIO);
    return 0;
}

static int32_t pty_add_group_target(
    PtyHandle *handle,
    pid_t group,
    pid_t groups[2],
    uint32_t *groupCount
) {
    uint32_t index;
    if (group <= 0) return -PTY_ESRCH;
    if (group == handle->daemonPgrp) return -PTY_EPERM;
    for (index = 0U; index < *groupCount; index += 1U) {
        if (groups[index] == group) return 0;
    }
    if (*groupCount >= 2U) return -PTY_E2BIG;
    groups[*groupCount] = group;
    *groupCount += 1U;
    return 0;
}

int32_t ptyKill(int32_t handleId, int32_t signalNumber, uint32_t targets) {
    PtyHandle *handle = pty_find_handle(handleId);
    pid_t groups[2];
    uint32_t groupCount = 0U;
    uint32_t index;
    int32_t result;
    int32_t firstError = 0;
    int sendChild;
    pid_t childCurrentGroup;

    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->pid <= 0) return -PTY_ECHILD;
    if (handle->childLost) return -PTY_ESRCH;
    if (handle->childReaped) return -PTY_ESRCH;
    if (signalNumber <= 0 || signalNumber >= PTY_NSIG) return -PTY_EINVAL;
    if (targets == 0U || (targets & ~PTY_KILL_ALL_TARGETS) != 0U) return -PTY_EINVAL;

    if ((targets & PTY_KILL_ORIGINAL_GROUP) != 0U) {
        result = pty_add_group_target(
            handle,
            handle->originalPgrp,
            groups,
            &groupCount
        );
        if (result < 0) return result;
    }
    if ((targets & PTY_KILL_FOREGROUND_GROUP) != 0U) {
        pid_t foreground;
        /*
         * The foreground group is only reachable through the master fd. When
         * the master is already closed (closeIo runs before the SIGKILL
         * escalation timer fires) or tcgetpgrp fails, skip this target rather
         * than aborting: the child and original group must still be signalled,
         * otherwise a leader that traps/ignores SIGHUP survives the escalation
         * and the session leaks.
         */
        if (handle->masterFd < 0) {
            /* no foreground target; fall through to child + original group */
        } else {
            foreground = tcgetpgrp(handle->masterFd);
            if (foreground > 0) {
                result = pty_add_group_target(
                    handle,
                    foreground,
                    groups,
                    &groupCount
                );
                if (result < 0) return result;
            }
        }
    }

    childCurrentGroup = getpgid(handle->pid);
    sendChild = (targets & PTY_KILL_CHILD) != 0U;
    if (sendChild && childCurrentGroup > 0) {
        for (index = 0U; index < groupCount; index += 1U) {
            if (groups[index] == childCurrentGroup) {
                sendChild = 0;
                break;
            }
        }
    }

    for (index = 0U; index < groupCount; index += 1U) {
        if (kill(-groups[index], signalNumber) < 0 && firstError == 0)
            firstError = pty_negative_errno_or(PTY_EIO);
    }
    if (sendChild && kill(handle->pid, signalNumber) < 0 && firstError == 0)
        firstError = pty_negative_errno_or(PTY_EIO);
    return firstError;
}

int32_t ptyWait(int32_t handleId, int32_t *exitCode, int32_t *signalNumber) {
    PtyHandle *handle = pty_find_handle(handleId);
    int status;
    pid_t waitResult;
    int terminalSignal;
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

    waitResult = waitpid(handle->pid, &status, PTY_WNOHANG);
    if (waitResult == 0) return 0;
    if (waitResult < 0) {
        /*
         * F5: a persistent waitpid failure (ECHILD — the child was reaped
         * elsewhere, e.g. a parent-death signal or an external reaper) means
         * we have lost ownership of the child. Mark the handle terminal so
         * ptyDestroy is permitted and ptyKill refuses to signal a possibly
         * reused PID. The caller (TS) treats this as a lost-child terminal
         * state with a forced exit code, not a retryable poll error.
         */
        if (pty_errno() == PTY_ECHILD_NATIVE) {
            handle->childLost = 1;
            /* Stable lost-child sentinel (the shim's PTY_ECHILD), independent
             * of the platform errno, so the TS caller keys on one value. */
            return -PTY_ECHILD;
        }
        return pty_negative_errno_or(PTY_EIO);
    }
    if (waitResult != handle->pid) {
        handle->childLost = 1;
        return -PTY_ECHILD;
    }

    terminalSignal = status & 0x7f;
    if (terminalSignal == 0) {
        handle->waitExitCode = (status >> 8) & 0xff;
        handle->waitSignal = 0;
    } else if (terminalSignal != 0x7f) {
        handle->waitSignal = terminalSignal;
        handle->waitExitCode = 128 + terminalSignal;
    } else {
        return -PTY_EIO;
    }
    handle->childReaped = 1;
    *exitCode = handle->waitExitCode;
    *signalNumber = handle->waitSignal;
    return 1;
}

int32_t ptyClose(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    int32_t firstError = 0;
    int32_t result;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    result = pty_close_one(&handle->masterFd);
    if (result < 0) firstError = result;
    if (handle->spawnStatus == 0 && handle->errorReadFd >= 0)
        handle->spawnStatus = -PTY_ECANCELED;
#if defined(PTY_TARGET_DARWIN)
    result = pty_darwin_reset_handshake(handle);
    if (result < 0 && firstError == 0) firstError = result;
#endif
    result = pty_close_one(&handle->errorReadFd);
    if (result < 0 && firstError == 0) firstError = result;
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
    if (previous == (PtyHandle *)PTY_NULL) ptyHandles = handle->next;
    else previous->next = handle->next;
    pty_free_environment(handle);
    free(handle);
    return closeResult;
}

#ifdef PTY_TESTING
int32_t ptyTestSetDarwinHandshakeFault(int32_t handleId, int32_t fault) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->spawnStarted) return -PTY_EBUSY;
#if defined(PTY_TARGET_DARWIN)
    if (fault < 0 || fault > PTY_TEST_DARWIN_FAIL_BEFORE_READY)
        return -PTY_EINVAL;
    handle->testDarwinHandshakeFault = fault;
    return 0;
#else
    (void)fault;
    return -PTY_ENOSYS;
#endif
}

int32_t ptyTestSetDarwinChildErrno(int32_t handleId, int32_t errorNumber) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (handle->spawnStarted) return -PTY_EBUSY;
#if defined(PTY_TARGET_DARWIN)
    if (errorNumber <= 0) return -PTY_EINVAL;
    handle->testDarwinChildErrno = errorNumber;
    return 0;
#else
    (void)errorNumber;
    return -PTY_ENOSYS;
#endif
}

int32_t ptyTestDarwinHandshakeState(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
#if defined(PTY_TARGET_DARWIN)
    return handle->descriptorHandshakeState;
#else
    return -PTY_ENOSYS;
#endif
}

int32_t ptyTestAdoptFd(int32_t handleId, int32_t fd) {
    PtyHandle *handle = pty_find_handle(handleId);
    int duplicateFd;
    int32_t result;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (fd < 0) return -PTY_EBADF;
    if (handle->spawnStarted || handle->masterFd >= 0) return -PTY_EBUSY;
    duplicateFd = fcntl(fd, PTY_F_DUPFD_CLOEXEC, 3);
    if (duplicateFd < 0) return pty_negative_errno_or(PTY_EIO);
    result = pty_set_nonblocking(duplicateFd);
    if (result < 0) {
        close(duplicateFd);
        return result;
    }
    handle->masterFd = duplicateFd;
    handle->spawnStarted = 1;
    return 0;
}

int32_t ptyTestSetInput(
    int32_t handleId,
    const uint8_t *data,
    uint32_t length,
    int32_t backpressured
) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (length > PTY_QUEUE_MAX) return -PTY_EINVAL;
    if (length > 0U && data == (const uint8_t *)PTY_NULL) return -PTY_EINVAL;
    if (backpressured != 0 && backpressured != 1) return -PTY_EINVAL;
    if (length > 0U) memcpy(handle->pendingInput, data, (size_t)length);
    handle->pendingLength = length;
    handle->inputBackpressured = backpressured;
    return 0;
}

int32_t ptyTestCopyInput(
    int32_t handleId,
    uint8_t *buffer,
    uint32_t capacity
) {
    PtyHandle *handle = pty_find_handle(handleId);
    uint32_t amount;
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (capacity > (uint32_t)PTY_INT32_MAX) return -PTY_EINVAL;
    if (capacity > 0U && buffer == (uint8_t *)PTY_NULL) return -PTY_EINVAL;
    amount = capacity < handle->pendingLength ? capacity : handle->pendingLength;
    if (amount > 0U) memcpy(buffer, handle->pendingInput, (size_t)amount);
    return (int32_t)amount;
}

int32_t ptyTestWriteCalls(int32_t handleId) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    return handle->testWriteCalls;
}

int32_t ptyTestFailWrites(
    int32_t handleId,
    int32_t errorNumber,
    uint32_t count
) {
    PtyHandle *handle = pty_find_handle(handleId);
    if (handle == (PtyHandle *)PTY_NULL) return -PTY_EBADF;
    if (errorNumber < 0) return -PTY_EINVAL;
    handle->testFailErrno = errorNumber;
    handle->testFailCount = count;
    return 0;
}
#endif
