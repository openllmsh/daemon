/* Linux sandbox ABI. Compile this source in Bun with TinyCC. */
typedef unsigned long usize;
typedef unsigned long long u64;
typedef unsigned int u32;
typedef int pid_t;
extern long syscall(long, ...);
extern int *__errno_location(void);
extern int open(const char *, int, ...);
extern int close(int);
extern long read(int, void *, usize);
extern long recv(int, void *, usize, int);
extern long write(int, const void *, usize);
extern long pread(int, void *, usize, long);
extern long lseek(int, long, int);
extern int fcntl(int, int, ...);
extern int snprintf(char *, usize, const char *, ...);
extern int sscanf(const char *, const char *, ...);
extern usize strlen(const char *);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, usize);
extern char *strstr(const char *, const char *);
extern char *strchr(const char *, int);
extern char *strrchr(const char *, int);
extern void *memset(void *, int, usize);
extern void *memcpy(void *, const void *, usize);
extern void *malloc(usize);
extern void free(void *);
extern long strtol(const char *, char **, int);
extern int getpid(void);
extern int getppid(void);
extern unsigned int getuid(void);
extern unsigned int getgid(void);
extern int prctl(int, ...);
extern int chdir(const char *);
extern int mount(const char *, const char *, const char *, unsigned long,
                 const void *);
extern int umount2(const char *, int);
extern int execve(const char *, char *const *, char *const *);
extern int socketpair(int, int, int, int *);
extern int setsockopt(int, int, int, const void *, unsigned int);
extern int getsockopt(int, int, int, void *, unsigned int *);
extern int pipe2(int *, int);
extern int rename(const char *, const char *);
extern int fsync(int);
extern int flock(int, int);
extern int unlink(const char *);
extern void *fdopen(int, const char *);
extern int fscanf(void *, const char *, ...);
extern int fclose(void *);
extern long readlink(const char *, char *, usize);
extern long getxattr(const char *, const char *, void *, usize);
extern int posix_spawn(int *, const char *, const void *, const void *,
                       char *const *, char *const *);
extern int posix_spawnattr_init(void *);
extern int posix_spawnattr_destroy(void *);
extern int posix_spawnattr_setflags(void *, short);
extern int posix_spawnattr_setsigmask(void *, const void *);
extern int posix_spawn_file_actions_init(void *);
extern int posix_spawn_file_actions_destroy(void *);
extern int posix_spawn_file_actions_adddup2(void *, int, int);
extern int posix_spawn_file_actions_addchdir_np(void *, const char *);
extern int sigemptyset(void *);
extern int sigaddset(void *, int);
extern int pthread_sigmask(int, const void *, void *);
extern void (*signal(int, void (*)(int)))(int);
extern int waitpid(int, int *, int);
extern int waitid(int, unsigned int, void *, int);
extern int clock_gettime(int, void *);

#define ERR (*__errno_location())
#define CLOEXEC 02000000
#define NONBLOCK 04000
#define OPATH 010000000
#define DIRECTORY 0200000
#define MAX_RECORD 1048576
#define MAX_ITEMS 2048
#define DEADLINE 10000
#define GRACE 2000
#define REAP 1000
#if defined(__x86_64__)
#define NR_TID 186
#define NR_EXIT 231
#define NR_SECCOMP 317
#define NR_CLONE 56
#define NR_UNSHARE 272
#define NR_SETNS 308
#define NR_MOUNT 165
#define NR_UMOUNT 166
#define NR_PIVOT 155
#define NR_CHROOT 161
#define ARCH 0xc000003e
#elif defined(__aarch64__)
#define NR_TID 178
#define NR_EXIT 94
#define NR_SECCOMP 277
#define NR_CLONE 220
#define NR_UNSHARE 97
#define NR_SETNS 268
#define NR_MOUNT 40
#define NR_UMOUNT 39
#define NR_PIVOT 41
#define NR_CHROOT 51
#define ARCH 0xc00000b7
#else
#error Unsupported Linux architecture
#endif
struct timespec {
  long sec;
  long nano;
};
struct pollfd {
  int fd;
  short events;
  short revents;
};
extern int poll(struct pollfd *, unsigned long, int);
struct iovec {
  void *base;
  usize length;
};
struct msghdr {
  void *name;
  unsigned int namelen;
  struct iovec *iov;
  usize iovlen;
  void *control;
  usize controllen;
  int flags;
};
struct cmsghdr {
  usize length;
  int level;
  int type;
};
extern long sendmsg(int, const struct msghdr *, int);
extern long recvmsg(int, struct msghdr *, int);
struct cred {
  int pid;
  unsigned int uid;
  unsigned int gid;
};
struct filter {
  unsigned short code;
  unsigned char jt;
  unsigned char jf;
  unsigned int k;
};
struct program {
  unsigned short length;
  struct filter *filter;
};
struct rule {
  u64 access;
  int fd;
} __attribute__((packed));
struct message {
  unsigned int magic;
  int stage;
  int value;
  int pid;
  char id[65];
  char digest[65];
  char lease[4096];
};
enum {
  TRACK = 1,
  IDENTITY,
  IDENTITY_OK,
  ENFORCED,
  REGISTER,
  ARMED,
  COMMIT,
  COMPLETE,
  ERROR,
  EXEC_ERROR,
  CANCEL
};
struct record {
  char *memory;
  char *id;
  char *digest;
  char *callerStart;
  char *outerStart;
  char *cwd;
  char *lease;
  char *boot;
  char *control;
  char *executableIdentity;
  char guardianStart[32];
  char initStart[32];
  int caller;
  int outer;
  char **self;
  char **args;
  char **env;
  char **ro;
  char **rw;
  char **bwrap;
  char **aliases;
  int naliases;
  char **tests;
  int ntests;
  int nself, nargs, nenv, nro, nrw, nbwrap;
};
static char *minimal[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "PWD=/",
                          0};
static long now(void) {
  struct timespec t;
  if (clock_gettime(1, &t))
    return -1;
  return t.sec * 1000 + t.nano / 1000000;
}
static void die(int code) {
  syscall(NR_EXIT, code);
  for (;;) {
  }
}
static int alive(int fd) {
  struct pollfd p = {fd, 1, 0};
  if (fd < 0)
    return 0;
  int result = poll(&p, 1, 0);
  /* An interrupted check does not prove that the process exited. */
  return result == 0 || (result < 0 && ERR == 4);
}
static int pidfd(int pid) { return (int)syscall(434, pid, 0); }
static int signalPid(int fd, int sig) {
  return (int)syscall(424, fd, sig, 0, 0);
}
static int fullWrite(int fd, const void *data, usize n) {
  const char *p = data;
  while (n) {
    long k = write(fd, p, n);
    if (k < 0 && ERR == 4)
      continue;
    if (k <= 0)
      return -1;
    p += k;
    n -= k;
  }
  return 0;
}
static int textFile(const char *path, char *out, int capacity) {
  int fd = open(path, CLOEXEC);
  if (fd < 0)
    return -1;
  int n = 0;
  while (n < capacity - 1) {
    long k = read(fd, out + n, capacity - 1 - n);
    if (k < 0 && ERR == 4)
      continue;
    if (k < 0) {
      close(fd);
      return -1;
    }
    if (!k)
      break;
    n += k;
  }
  close(fd);
  out[n] = 0;
  return n == capacity - 1 ? -1 : n;
}
static int number(const char *s) {
  char *end;
  long value = strtol(s, &end, 10);
  return *s && !*end && value >= 0 && value < 2147483647 ? (int)value : -1;
}
static char *next(char **cursor, char *end) {
  char *start = *cursor, *p = start;
  while (p < end && *p)
    p++;
  if (p == end)
    return 0;
  *cursor = p + 1;
  return start;
}
static int vector(char **cursor, char *end, char ***out) {
  char *count = next(cursor, end);
  int n = count ? number(count) : -1;
  if (n < 0 || n > MAX_ITEMS)
    return -1;
  char **v = malloc((n + 1) * sizeof(char *));
  if (!v)
    return -1;
  for (int i = 0; i < n; i++) {
    v[i] = next(cursor, end);
    if (!v[i]) {
      free(v);
      return -1;
    }
  }
  v[n] = 0;
  *out = v;
  return n;
}
static int parse(char *data, int length, struct record *r) {
  if (length < 1 || length > MAX_RECORD)
    return -1;
  char *p = data, *end = data + length;
  char *version = next(&p, end);
  if (!version || strcmp(version, "SBX1"))
    return -1;
  memset(r, 0, sizeof(*r));
  r->memory = data;
  r->id = next(&p, end);
  r->digest = next(&p, end);
  char *caller = next(&p, end);
  r->callerStart = next(&p, end);
  char *outer = next(&p, end);
  r->outerStart = next(&p, end);
  r->cwd = next(&p, end);
  r->lease = next(&p, end);
  r->boot = next(&p, end);
  r->control = next(&p, end);
  r->executableIdentity = next(&p, end);
  if (!r->executableIdentity || !r->control || !caller || !outer ||
      strlen(r->id) != 64 || strlen(r->digest) != 64)
    return -1;
  r->caller = number(caller);
  r->outer = number(outer);
  if (r->caller <= 0 || r->outer <= 0 || r->cwd[0] != '/' || r->lease[0] != '/')
    return -1;
  r->nself = vector(&p, end, &r->self);
  r->nargs = vector(&p, end, &r->args);
  r->nenv = vector(&p, end, &r->env);
  r->nro = vector(&p, end, &r->ro);
  r->nrw = vector(&p, end, &r->rw);
  r->nbwrap = vector(&p, end, &r->bwrap);
  r->naliases = vector(&p, end, &r->aliases);
  r->ntests = vector(&p, end, &r->tests);
#ifndef SBX_TESTING
  if (r->ntests != 0)
    return -1;
#endif
  return p == end && r->nself > 0 && r->nargs > 0 && r->nenv > 0 &&
                 r->nro >= 0 && r->nrw >= 0 && r->nbwrap > 0 &&
                 r->naliases >= 0 && (r->ntests == 0 || r->ntests == 6)
             ? 0
             : -1;
}
static int sealed(const void *data, int length) {
#if defined(__aarch64__)
  int fd = (int)syscall(279, "openllm-sandbox", 3);
#else
  int fd = (int)syscall(319, "openllm-sandbox", 3);
#endif
  if (fd < 0)
    return -1;
  if (fullWrite(fd, data, length) || lseek(fd, 0, 0) < 0 ||
      fcntl(fd, 1033, 15) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}
static int readRecord(int fd, struct record *r) {
  if (fcntl(fd, 1034) != 15)
    return -1;
  long length = lseek(fd, 0, 2);
  if (length < 1 || length > MAX_RECORD)
    return -1;
  char *data = malloc(length);
  if (!data)
    return -1;
  if (pread(fd, data, length, 0) != length)
    return -1;
  return parse(data, (int)length, r);
}
static int fault(struct record *, const char *);
static int sendRecord(int socket, struct record *r, int stage, int value,
                      int pid, const int *fds, int count) {
  if (count < 0 || count > 3)
    return -1;
  struct message m = {0x53425831, stage, value, pid, {0}, {0}};
  memcpy(m.id, r->id, 65);
  memcpy(m.digest, r->digest, 65);
  if (r->lease) {
    if (strlen(r->lease) >= sizeof(m.lease))
      return -1;
    memcpy(m.lease, r->lease, strlen(r->lease) + 1);
  }
  struct iovec iov = {&m, sizeof(m)};
  unsigned long control[8] = {0};
  struct msghdr h = {0, 0, &iov, 1, 0, 0, 0};
  if (count) {
    struct cmsghdr *c = (void *)control;
    c->length = 16 + count * sizeof(int);
    c->level = 1;
    c->type = 1;
    memcpy((char *)control + 16, fds, count * sizeof(int));
    h.control = control;
    h.controllen = (c->length + 7) & ~7;
  }
  if (stage == IDENTITY && fault(r, "identity_credentials")) {
    usize offset = h.controllen;
    struct cmsghdr *c = (void *)((char *)control + offset);
    c->length = 28;
    c->level = 1;
    c->type = 2;
    struct cred forged = {getpid() + 1000000, getuid(), getgid()};
    memcpy((char *)c + 16, &forged, 12);
    h.control = control;
    h.controllen = offset + 32;
  }
  return sendmsg(socket, &h, 0x4000) == sizeof(m) ? 0 : -1;
}
static int receive(int socket, struct record *r, struct message *m, int *fds,
                   int expected, struct cred *credential) {
  unsigned long control[32] = {0};
  struct iovec iov = {m, sizeof(*m)};
  struct msghdr h = {0, 0, &iov, 1, control, sizeof(control), 0};
  long n;
  int interrupted = 0;
  do {
    n = recvmsg(socket, &h, 0x40000000 | 0x40);
  } while (n < 0 && ERR == 4 && ++interrupted < 32);
  if (n < 0 && (ERR == 11 || ERR == 4))
    return 0;
  if (n < 0)
    return -1;
  int count = 0, creds = 0, bad = n != sizeof(*m) || (h.flags & (8 | 32));
  for (usize off = 0; off + 16 <= h.controllen;) {
    struct cmsghdr *c = (void *)((char *)control + off);
    if (c->length < 16 || off + c->length > h.controllen) {
      bad = 1;
      break;
    }
    if (c->level == 1 && c->type == 1) {
      int k = (c->length - 16) / 4;
      int *v = (void *)((char *)c + 16);
      for (int j = 0; j < k; j++) {
        if (count < expected)
          fds[count] = v[j];
        else {
          close(v[j]);
          bad = 1;
        }
        count++;
      }
    } else if (c->level == 1 && c->type == 2 && c->length == 28 && !creds) {
      memcpy(credential, (char *)c + 16, 12);
      creds = 1;
    } else
      bad = 1;
    off += (c->length + 7) & ~7;
  }
  if (bad || count != expected || !creds || credential->uid != getuid() ||
      credential->gid != getgid() || m->magic != 0x53425831 || m->id[64] ||
      m->digest[64] || strcmp(m->id, r->id) || strcmp(m->digest, r->digest)) {
    for (int i = 0; i < count && i < expected; i++)
      close(fds[i]);
    return -1;
  }
  return 1;
}
static int pair(int fds[2]) {
  if (socketpair(1, 5 | CLOEXEC, 0, fds))
    return -1;
  int yes = 1;
  return setsockopt(fds[0], 1, 16, &yes, 4) ||
                 setsockopt(fds[1], 1, 16, &yes, 4)
             ? -1
             : 0;
}
static int identity(int pid, int *parent, char *start) {
  char path[80], buf[4096];
  snprintf(path, sizeof(path), "/proc/%d/stat", pid);
  if (textFile(path, buf, sizeof(buf)) < 0)
    return -1;
  char *p = strrchr(buf, ')');
  if (!p || p[1] != ' ')
    return -1;
  p += 2;
  for (int field = 3; field <= 22; field++) {
    char *end = strchr(p, ' ');
    if (!end)
      return -1;
    if (field == 4) {
      *end = 0;
      *parent = number(p);
      *end = ' ';
    }
    if (field == 22) {
      if (end - p > 31)
        return -1;
      memcpy(start, p, end - p);
      start[end - p] = 0;
      return 0;
    }
    p = end + 1;
  }
  return -1;
}
static int checkOwner(int pid, const char *start) {
  char found[32];
  int parent;
  int fd = pidfd(pid);
  if (fd < 0 || identity(pid, &parent, found) || strcmp(start, found) ||
      !alive(fd) || signalPid(fd, 0)) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  return fd;
}
static int fault(struct record *r, const char *name) {
#ifdef SBX_TESTING
  return r->ntests == 6 && !strcmp(r->tests[5], name);
#else
  return 0;
#endif
}
static int testSuppressAdoption = 0;
static void testBarrier(struct record *r, const char *phase, int monitor) {
#ifdef SBX_TESTING
  if (r->ntests != 6 || strcmp(r->tests[0], phase))
    return;
  int fd = open(r->tests[2], 1 | 64 | 512 | CLOEXEC, 0600);
  if (fd < 0)
    die(78);
  char record[128];
  int n = snprintf(record, sizeof(record), "{\"guardian\":%d,\"monitor\":%d}\n",
                   getpid(), monitor);
  if (fullWrite(fd, record, n))
    die(78);
  close(fd);
  fd = open(r->tests[1], CLOEXEC | NONBLOCK);
  if (fd < 0)
    die(78);
  long limit = now() + DEADLINE;
  while (now() < limit) {
    char value;
    if (read(fd, &value, 1) == 1)
      break;
    poll(0, 0, 5);
  }
  close(fd);
#endif
}
static int fdIdentity(int fd, int expected, int inner) {
  char path[80], buf[4096];
  snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
  if (textFile(path, buf, sizeof(buf)) < 0)
    return -1;
  char *p = strstr(buf, "Pid:\t"), *ns = strstr(buf, "NSpid:\t");
  int pid = -1, a = -1, b = -1;
  char extra = 0;
  if (!p || !ns || sscanf(p, "Pid:\t%d", &pid) != 1 || pid != expected)
    return -1;
  char *end = strchr(ns, '\n');
  if (end)
    *end = 0;
  int fields = sscanf(ns, "NSpid:\t%d %d %c", &a, &b, &extra);
  if (a != expected || (inner ? fields != 2 || b != inner : fields != 1))
    return -1;
  return alive(fd) && !signalPid(fd, 0) ? 0 : -1;
}
static int namespaceLink(int pid, const char *kind, char *buf) {
  char path[80];
  snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, kind);
  long n = readlink(path, buf, 127);
  if (n <= 0 || n >= 127)
    return -1;
  buf[n] = 0;
  return 0;
}
static int validateIdentity(int vendor, int init, int monitor, int *fds) {
  if (fdIdentity(fds[0], vendor, 2) || fdIdentity(fds[1], init, 1))
    return -1;
  char vs[32], is[32], vs2[32], is2[32];
  int parent;
  if (identity(vendor, &parent, vs) || parent != init ||
      identity(init, &parent, is) || parent != monitor)
    return -1;
  const char *names[] = {"pid", "user", "mnt"};
  for (int k = 0; k < 3; k++) {
    char a[128], b[128], c[128];
    if (namespaceLink(vendor, names[k], a) ||
        namespaceLink(init, names[k], b) ||
        namespaceLink(getpid(), names[k], c) || strcmp(a, b) || !strcmp(a, c))
      return -1;
  }
  if (identity(vendor, &parent, vs2) || strcmp(vs, vs2) ||
      identity(init, &parent, is2) || strcmp(is, is2))
    return -1;
  return alive(fds[0]) && alive(fds[1]) ? 0 : -1;
}
static int environment(int pid) {
  char path[80], buf[1024];
  snprintf(path, sizeof(path), "/proc/%d/environ", pid);
  int n = textFile(path, buf, sizeof(buf));
  if (n < 0)
    return -1;
  int mask = 0;
  for (int i = 0; i < n;) {
    int found = 0;
    for (int k = 0; k < 4; k++)
      if (!strcmp(buf + i, minimal[k])) {
        if (mask & (1 << k))
          return -1;
        mask |= 1 << k;
        found = 1;
      }
    if (!found)
      return -1;
    i += strlen(buf + i) + 1;
  }
  return mask == 15 ? 0 : -1;
}
static int spawn(char **argv, int *fds, int count) {
  unsigned long attrs[128] = {0}, actions[128] = {0}, mask[16] = {0};
  int copies[8], pid = -1;
  if (count > 8 || syscall(NR_TID) != getpid())
    return -1;
  for (int i = 0; i < count; i++) {
    copies[i] = fcntl(fds[i], 1030, 64);
    if (copies[i] < 0) {
      for (int j = 0; j < i; j++)
        close(copies[j]);
      return -1;
    }
  }
  int error = posix_spawnattr_init(attrs);
  if (!error)
    error = posix_spawn_file_actions_init(actions);
  if (!error)
    error = sigemptyset(mask);
  if (!error)
    error = posix_spawnattr_setsigmask(attrs, mask);
  if (!error)
    error = posix_spawnattr_setflags(attrs, 0x80 | 8);
  if (!error)
    error = posix_spawn_file_actions_addchdir_np(actions, "/");
  for (int i = 0; !error && i < count; i++)
    error = posix_spawn_file_actions_adddup2(actions, copies[i], 3 + i);
  if (!error)
    error = posix_spawn(&pid, argv[0], actions, attrs, argv, minimal);
  posix_spawn_file_actions_destroy(actions);
  posix_spawnattr_destroy(attrs);
  for (int i = 0; i < count; i++)
    close(copies[i]);
  return error ? -1 : pid;
}
static int signalWriter = -1;
static void caughtSignal(int value) {
  int saved = ERR;
  if (value != 13 && signalWriter >= 0)
    write(signalWriter, &value, sizeof(value));
  ERR = saved;
}
static int signals(void) {
  int fds[2];
  if (pipe2(fds, CLOEXEC | NONBLOCK))
    return -1;
  signalWriter = fds[1];
  if (signal(1, caughtSignal) == (void *)-1 ||
      signal(2, caughtSignal) == (void *)-1 ||
      signal(15, caughtSignal) == (void *)-1 ||
      signal(13, caughtSignal) == (void *)-1)
    return -1;
  return fds[0];
}
static int pollSignal(int fd) {
  int value = 0;
  return read(fd, &value, sizeof(value)) == sizeof(value) ? value : 0;
}
static int leaseLockPath(const char *path, char *lock) {
  const char *name = strrchr(path, '/');
  if (!name || strlen(path) > 4000 || name - path < 15 ||
      strncmp(name - 15, "/sandbox-leases", 15) ||
      strlen(name) < 6 || strcmp(name + strlen(name) - 5, ".json"))
    return -1;
  snprintf(lock, 4096, "%.*s/tmp/%.*s/.owner-lock", (int)(name - path - 15), path,
           (int)strlen(name) - 6, name + 1);
  return 0;
}
int sandboxLeaseLock(const char *path, int create) {
  char lock[4096];
  if (leaseLockPath(path, lock))
    return -1;
  int fd = open(lock, 2 | CLOEXEC | (create ? 64 : 0), 0600);
  if (fd >= 0 && flock(fd, 2 | 4)) {
    close(fd);
    return -1;
  }
  return fd;
}
static int lease(struct record *r, int guardian, int init, int complete) {
  char temp[4096], body[1024];
  if (strlen(r->lease) > 4000)
    return -1;
  int parent;
  if (guardian > 0 && !*r->guardianStart)
    identity(guardian, &parent, r->guardianStart);
  if (init > 0 && !*r->initStart)
    identity(init, &parent, r->initStart);
  snprintf(temp, sizeof(temp), "%s.%d", r->lease, getpid());
  int n = snprintf(
      body, sizeof(body),
      "{\"v\":2,\"pid\":%d,\"startIdentity\":\"boot:%s:%s\",\"launchId\":\"%"
      "s\",\"guardianPid\":%d,\"initPid\":%d,\"guardianStartIdentity\":\"boot:%"
      "s:%s\",\"initStartIdentity\":\"boot:%s:%s\",\"cleanupComplete\":%s}\n",
      r->outer, r->boot, r->outerStart, r->id, guardian, init, r->boot,
      r->guardianStart, r->boot, r->initStart, complete ? "true" : "false");
  int fd = open(temp, 1 | 64 | 512 | CLOEXEC, 0600);
  if (fd < 0)
    return -1;
  int rc = fullWrite(fd, body, n) || fsync(fd);
  close(fd);
  if (rc)
    return -1;
  if (rename(temp, r->lease))
    return -1;
  if (complete) {
    if (!leaseLockPath(r->lease, temp))
      unlink(temp);
  }
  return 0;
}
/* Inspect each child before reaping. Adoption supplies the launch boundary. */
static int reapChildStream(void *stream, int force, int target, int *result) {
  int child;
  while (fscanf(stream, "%d", &child) == 1) {
    char start[32], check[32];
    int parent;
    int fd = pidfd(child);
    if (fd < 0)
      continue;
    if (identity(child, &parent, start) || parent != getpid() ||
        identity(child, &parent, check) || strcmp(start, check)) {
      close(fd);
      fclose(stream);
      return -1;
    }
    int suppress = 0;
#ifdef SBX_TESTING
    if (testSuppressAdoption) {
      char childNs[128], selfNs[128];
      suppress = !namespaceLink(child, "pid", childNs) &&
                 !namespaceLink(getpid(), "pid", selfNs) &&
                 strcmp(childNs, selfNs);
    }
#endif
    if (force && !suppress)
      signalPid(fd, 9);
    unsigned long observed[16] = {0};
    if (waitid(1, child, observed, 4 | 1 | 0x1000000)) {
      close(fd);
      fclose(stream);
      return -1;
    }
    int status;
    int got = waitpid(child, &status, 1);
    close(fd);
    if (got == child && child == target)
      *result = (status & 127) ? 128 + (status & 127) : (status >> 8) & 255;
  }
  fclose(stream);
  int status;
  int got = waitpid(-1, &status, 1);
  if (got > 0 && got == target)
    *result = (status & 127) ? 128 + (status & 127) : (status >> 8) & 255;
  return got < 0 && ERR == 10 ? 1 : 0;
}
static int reapChildren(int force, int target, int *result) {
  char path[96];
  snprintf(path, sizeof(path), "/proc/self/task/%d/children", getpid());
  int children = open(path, CLOEXEC);
  if (children < 0)
    return -1;
  void *stream = fdopen(children, "r");
  if (!stream) {
    close(children);
    return -1;
  }
  return reapChildStream(stream, force, target, result);
}
static void cleanup(struct record *r, int guardian, int init, int initfd,
                    int monitorfd, int target, int *result) {
  long limit = now() + REAP;
  int reported = 0;
  for (;;) {
    if (initfd >= 0 && !fault(r, "skip_init_kill"))
      signalPid(initfd, 9);
    if (monitorfd >= 0)
      signalPid(monitorfd, 9);
    int done = reapChildren(1, target, result);
    if (done == 1 && !alive(initfd) && !alive(monitorfd))
      break;
    if (!reported && now() >= limit) {
      const char *s = "SANDBOX_UNAVAILABLE: reap_unconfirmed\n";
      fullWrite(2, s, strlen(s));
      reported = 1;
    }
    poll(0, 0, reported ? 100 : 20);
  }
  lease(r, guardian, init, 1);
}
static int fail(int socket, struct record *r, int reason) {
  sendRecord(socket, r, ERROR, reason, 0, 0, 0);
  return 78;
}
static int failEmpty(int socket, struct record *r, int reason) {
  lease(r, 0, 0, 1);
  if (socket >= 0)
    return fail(socket, r, reason);
  const char *message = "SANDBOX_UNAVAILABLE: SETUP_FAILED\n";
  fullWrite(2, message, strlen(message));
  return 78;
}
int sandboxFileCapabilities(const char *path) {
  char buf[128];
  long n = getxattr(path, "security.capability", buf, sizeof(buf));
  return n >= 0 ? 1 : ERR == 61 || ERR == 95 ? 0 : -1;
}
static int namespaceFilter(void) {
  struct filter f[128];
  int n = 0;
#define B(code, a, b, k)                                                       \
  do {                                                                         \
    struct filter x = {code, a, b, k};                                         \
    f[n++] = x;                                                                \
  } while (0)
  B(0x20, 0, 0, 4);
  B(0x15, 1, 0, ARCH);
  B(0x06, 0, 0, 0x80000000);
  B(0x20, 0, 0, 0);
#if defined(__x86_64__)
  B(0x45, 0, 1, 0x40000000);
  B(0x06, 0, 0, 0x80000000);
#endif
  int denied[] = {NR_UNSHARE, NR_SETNS, NR_MOUNT, NR_UMOUNT, NR_PIVOT,
                  NR_CHROOT,  442,      428,      429,       430,
                  431,        432,      433};
  for (int i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) {
    B(0x15, 0, 1, denied[i]);
    B(0x06, 0, 0, 0x50001);
  }
  B(0x15, 0, 1, 435);
  B(0x06, 0, 0, 0x50026);
  B(0x15, 0, 3, NR_CLONE);
  B(0x20, 0, 0, 16);
  B(0x45, 0, 1, 0x7e020080);
  B(0x06, 0, 0, 0x50001);
  B(0x06, 0, 0, 0x7fff0000);
#undef B
  struct program program = {n, f};
  return syscall(NR_SECCOMP, 1, 1, &program) == 0 ? 0 : -1;
}
static int capabilities(void) {
  if (prctl(47, 4, 0, 0, 0))
    return -1;
  for (int c = 0; c < 64; c++) {
    if (c == 8)
      continue;
    int present = prctl(23, c, 0, 0, 0);
    if (present < 0 && ERR == 22)
      continue;
    if (present < 0 || prctl(24, c, 0, 0, 0))
      return -1;
  }
  if (prctl(24, 8, 0, 0, 0))
    return -1;
  unsigned int header[2] = {0x20080522, 0}, data[6] = {0};
#if defined(__x86_64__)
  if (syscall(126, header, data) || syscall(125, header, data))
    return -1;
#else
  if (syscall(91, header, data) || syscall(90, header, data))
    return -1;
#endif
  for (int i = 0; i < 6; i++)
    if (data[i])
      return -1;
  for (int c = 0; c < 64; c++) {
    int b = prctl(23, c, 0, 0, 0);
    if (b > 0)
      return -1;
    if (b < 0 && ERR != 22)
      return -1;
    int a = prctl(47, 1, c, 0, 0);
    if (a > 0)
      return -1;
    if (a < 0 && ERR != 22)
      return -1;
  }
  return 0;
}
static int finalMount(struct record *r) {
  if (mount(0, "/", 0, (1UL << 18) | 16384, 0))
    return -1;
  if (mount("devpts", "/dev/pts", "devpts", 2 | 8,
            "newinstance,ptmxmode=0666,mode=0620"))
    return -1;
  for (int i = 0; i < r->naliases; i++) {
    if (r->aliases[i][0] != '/' || !strcmp(r->aliases[i], "/proc") ||
        umount2(r->aliases[i], 2))
      return -1;
  }
  if (mount("proc", "/proc", "proc", 1 | 2 | 4 | 8, "subset=pid"))
    return -1;
#ifdef SBX_TESTING
  if (fault(r, "proc_alias") && mount("/proc", r->tests[1], 0, 4096, 0))
    return -1;
#endif
  /* Read the visible mount ID. Mount table order does not select the top. */
  int proc = open("/proc", OPATH | CLOEXEC | DIRECTORY);
  if (proc < 0)
    return -1;
  char infoPath[64], info[4096];
  snprintf(infoPath, sizeof(infoPath), "/proc/self/fdinfo/%d", proc);
  int infoResult = textFile(infoPath, info, sizeof(info));
  close(proc);
  u64 visible = 0;
  char *mountId = infoResult < 0 ? 0 : strstr(info, "\nmnt_id:");
  if (!mountId || sscanf(mountId, "\nmnt_id: %llu", &visible) != 1)
    return -1;
  char *buf = malloc(MAX_RECORD);
  if (!buf)
    return -1;
  if (textFile("/proc/self/mountinfo", buf, MAX_RECORD) < 0)
    return -1;
  int found = 0;
  char *p = buf;
  char options[256] = {0};
  int subset = 0;
  while (*p) {
    char *end = strchr(p, '\n');
    if (!end)
      return -1;
    *end = 0;
    if (strstr(p, " shared:") || strstr(p, " master:"))
      return -1;
    char *type = strstr(p, " - proc ");
    if (type) {
      char target[4096], opts[256];
      u64 id;
      if (sscanf(p, "%llu %*d %*s %*s %4095s %255s", &id, target, opts) != 3 ||
          strcmp(target, "/proc"))
        return -1;
      if (id == visible) {
        found = 1;
        memcpy(options, opts, strlen(opts) + 1);
        subset = strstr(type, "subset=pid") != 0;
      }
    }
    p = end + 1;
  }
  free(buf);
  if (!found || !subset || !strstr(options, "ro,") ||
      !strstr(options, "nosuid") || !strstr(options, "nodev") ||
      !strstr(options, "noexec"))
    return -1;
  const char *absent[] = {"/proc/sys",     "/proc/net",  "/proc/cpuinfo",
                          "/proc/meminfo", "/proc/stat", "/proc/uptime",
                          "/proc/loadavg"};
  for (int i = 0; i < 7; i++) {
    int fd = open(absent[i], OPATH | CLOEXEC);
    if (fd >= 0) {
      close(fd);
      return -1;
    }
    if (ERR != 2)
      return -1;
  }
  char maps[32];
  int fd = open("/proc/self/maps", CLOEXEC);
  if (fd < 0)
    return -1;
  long n = read(fd, maps, sizeof(maps));
  close(fd);
  return n > 0 ? 0 : -1;
}
static int addRule(int ruleset, char *path, u64 mask) {
  int fd = open(path, OPATH | CLOEXEC | DIRECTORY);
  if (fd < 0) {
    if (ERR != 20)
      return -1;
    fd = open(path, OPATH | CLOEXEC);
    mask &= 0x1c007;
  }
  if (fd < 0)
    return -1;
  struct rule rule = {mask, fd};
  int rc = (int)syscall(445, ruleset, 1, &rule, 0);
  close(fd);
  return rc;
}
static u64 landlockAccessFs(int abi) {
  if (abi < 1)
    return 0;
  u64 mask = 0x1fff;
  if (abi >= 2)
    mask |= 1ULL << 13; /* REFER */
  if (abi >= 3)
    mask |= 1ULL << 14; /* TRUNCATE */
  if (abi >= 5)
    mask |= 1ULL << 15; /* IOCTL_DEV */
  if (abi >= 9)
    mask |= 1ULL << 16; /* RESOLVE_UNIX */
  return mask;
}
int sandboxExecutableIdentity(const char *path, char *out) {
  unsigned long data[32] = {0};
#if defined(__aarch64__)
  long result = syscall(291, -100, path, 0, 0x103, data);
#else
  long result = syscall(332, -100, path, 0, 0x103, data);
#endif
  const char *bytes = (const char *)data;
  if (result || (*(unsigned int *)bytes & 0x103) != 0x103 ||
      (*(unsigned short *)(bytes + 28) & 0170000) != 0100000)
    return -1;
  snprintf(out, 96, "%llu:%u:%u", *(u64 *)(bytes + 32),
           *(unsigned int *)(bytes + 136), *(unsigned int *)(bytes + 140));
  return 0;
}
static int helper(struct record *r) {
  int socket = 4;
  if (getpid() != 2 || syscall(NR_TID) != getpid() || environment(getpid()))
    die(fail(socket, r, 10));
  char executableIdentity[96];
  if (sandboxExecutableIdentity(r->args[0], executableIdentity) ||
      strcmp(executableIdentity, r->executableIdentity) ||
      fault(r, "executable_identity"))
    die(fail(socket, r, 10));
  if (fault(r, "mount") || finalMount(r))
    die(fail(socket, r, 11));
  int fds[3] = {pidfd(getpid()), pidfd(1), -1};
  int descriptorCount = 2;
  if (fault(r, "identity_extra")) {
    fds[2] = pidfd(getpid());
    descriptorCount = 3;
  }
  if (fault(r, "identity_swap")) {
    int fd = fds[0];
    fds[0] = fds[1];
    fds[1] = fd;
  }
  if (fault(r, "setup_timeout"))
    poll(0, 0, DEADLINE + 1000);
  if (fds[0] < 0 || fds[1] < 0 ||
      sendRecord(socket, r, IDENTITY, 0, 2, fds, descriptorCount))
    die(78);
  if (fault(r, "identity_duplicate"))
    sendRecord(socket, r, IDENTITY, 0, 2, fds, descriptorCount);
  close(fds[0]);
  close(fds[1]);
  if (fds[2] >= 0)
    close(fds[2]);
  struct message m;
  struct cred c;
  long limit = now() + DEADLINE;
  int got = 0;
  while (now() < limit) {
    got = receive(socket, r, &m, 0, 0, &c);
    if (got)
      break;
    struct pollfd p = {socket, 1, 0};
    poll(&p, 1, 20);
  }
  if (got != 1 || m.stage != IDENTITY_OK || c.pid != 0)
    die(fail(socket, r, 12));
  int abi = (int)syscall(444, 0, 0, 1);
  if (abi < 1)
    die(fail(socket, r, 13));
  u64 mask = landlockAccessFs(abi);
  struct {
    u64 handled_access_fs;
  } attr = {mask};
  int ruleset = (int)syscall(444, &attr, sizeof(attr), 0);
  if (ruleset < 0)
    die(fail(socket, r, 14));
  if (fault(r, "rule"))
    die(fail(socket, r, 15));
  for (int i = 0; i < r->nro; i++) {
    u64 access = 13;
    if (!strcmp(r->ro[i], "/run/systemd/resolve") ||
        !strcmp(r->ro[i], "/run/resolvconf"))
      access |= mask & (1ULL << 16);
    if (addRule(ruleset, r->ro[i], access))
      die(fail(socket, r, 15));
  }
  for (int i = 0; i < r->nrw; i++)
    if (addRule(ruleset, r->rw[i], mask))
      die(fail(socket, r, 15));
  if (addRule(ruleset, "/proc", 12))
    die(fail(socket, r, 15));
  if (chdir(r->cwd) || syscall(436, 3, ~0U, 2 | 4))
    die(fail(socket, r, 16));
  if (capabilities() || prctl(38, 1, 0, 0, 0) || fault(r, "tsync") ||
      namespaceFilter())
    die(fail(socket, r, 17));
  if (fault(r, "restriction") || syscall(446, ruleset, 0))
    die(fail(socket, r, 18));
  close(ruleset);
  if (sendRecord(socket, r, ENFORCED, abi, (int)mask, 0, 0))
    die(78);
  got = 0;
  while (now() < limit) {
    got = receive(socket, r, &m, 0, 0, &c);
    if (got)
      break;
    struct pollfd p = {socket, 1, 0};
    poll(&p, 1, 20);
  }
  if (got != 1 || m.stage != COMMIT || c.pid != 0)
    die(fail(socket, r, 19));
  if (syscall(436, 3, 3, 0) || syscall(436, 5, ~0U, 0))
    die(fail(socket, r, 20));
  unsigned long empty[16] = {0};
  sigemptyset(empty);
  if (pthread_sigmask(2, empty, 0))
    die(fail(socket, r, 21));
  execve(r->args[0], r->args, r->env);
  sendRecord(socket, r, EXEC_ERROR, 127, 0, 0, 0);
  die(127);
  return 127;
}
static int guardian(struct record *r) {
#ifdef SBX_TESTING
  if (fault(r, "skip_init_kill"))
    testSuppressAdoption = 1;
#endif
  int socket = 4, helperSocket = 5, signal = signals(), caller = -1, outer = -1;
  if (syscall(NR_TID) != getpid() || signal < 0 || prctl(1, 0, 0, 0, 0) ||
      prctl(36, 1, 0, 0, 0))
    return failEmpty(socket, r, 30);
  caller = checkOwner(r->caller, r->callerStart);
  outer = checkOwner(r->outer, r->outerStart);
  if (caller < 0 || outer < 0)
    return failEmpty(socket, r, 31);
  /* The inherited lock covers the gap between spawn and this record. */
  if (lease(r, getpid(), 0, 0))
    return failEmpty(socket, r, 31);
  int status[2];
  if (pipe2(status, CLOEXEC | NONBLOCK))
    return failEmpty(socket, r, 32);
  int fds[6] = {3, helperSocket, 6, status[1], -1, -1};
  int fdCount = 4;
#ifdef SBX_TESTING
  if (r->ntests == 6 && *r->tests[3]) {
    fds[4] = open(r->tests[3], CLOEXEC);
    char infoPath[4096];
    snprintf(infoPath, sizeof(infoPath), "%s.bwrap", r->tests[2]);
    fds[5] = open(infoPath, 1 | 64 | 512 | CLOEXEC, 0600);
    if (fds[4] < 0 || fds[5] < 0)
      return failEmpty(socket, r, 32);
    fdCount = 6;
  }
#endif
  char **argv = malloc((r->nself + 7) * sizeof(char *));
  if (!argv)
    return failEmpty(socket, r, 33);
  argv[0] = r->bwrap[0];
  argv[1] = "--args";
  argv[2] = "5";
  argv[3] = "--";
  for (int i = 0; i < r->nself; i++)
    argv[4 + i] = r->self[i];
  argv[4 + r->nself] = "--sandbox-helper";
  argv[5 + r->nself] = 0;
  int monitor = spawn(argv, fds, fdCount);
  if (fdCount == 6) {
    close(fds[4]);
    close(fds[5]);
  }
  close(helperSocket);
  close(status[1]);
  close(6);
  if (monitor < 0)
    return failEmpty(socket, r, 33);
  testBarrier(r, "guardian-spawn", monitor);
  int monitorfd = pidfd(monitor), initfd = -1, vendorfd = -1, init = 0,
      result = 78, armed = 0, committed = 0, failed = 0;
  if (monitorfd < 0)
    failed = 1;
  long setup = now() + DEADLINE, cancel = 0;
  char info[8192] = {0};
  int used = 0;
  while (!failed) {
    if (!alive(outer)) {
      failed = 1;
      break;
    }
    if (!alive(caller) && !cancel) {
      if (!committed) {
        failed = 1;
        break;
      }
      signalPid(vendorfd, 15);
      cancel = now() + GRACE;
    }
    if ((!committed && now() >= setup) || (cancel && now() >= cancel)) {
      failed = 1;
      break;
    }
    if (!init) {
      long n = read(status[0], info + used, sizeof(info) - 1 - used);
      if (n > 0) {
        used += n;
        info[used] = 0;
        char *p = strstr(info, "\"child-pid\"");
        if (p) {
          p = strchr(p, ':');
          if (p) {
            init = (int)strtol(p + 1, 0, 10);
            int parent;
            char start[32];
            initfd = pidfd(init);
            if (init <= 0 || initfd < 0 || identity(init, &parent, start) ||
                parent != monitor || fdIdentity(initfd, init, 1) ||
                environment(init)) {
              failed = 1;
              break;
            }
            int tracked[2] = {monitorfd, initfd};
            testBarrier(r, "descriptor-transfer", monitor);
            if (lease(r, getpid(), init, 0) ||
                sendRecord(socket, r, TRACK, init,
                           fault(r, "identity_parent") ? getpid() : monitor,
                           tracked, 2)) {
              failed = 1;
              break;
            }
          }
        }
        if (used >= sizeof(info) - 1) {
          failed = 1;
          break;
        }
      }
    }
    struct pollfd p = {socket, 1, 0};
    if (poll(&p, 1, 0) > 0) {
      struct message m;
      struct cred c;
      int received[2];
      int got = receive(socket, r, &m, received, armed ? 0 : 2, &c);
      if (got == 0)
        continue;
      if (got != 1 || c.pid != r->outer) {
        failed = 1;
        break;
      }
      if (!armed && m.stage == REGISTER && init && m.value == init) {
        int vendor = m.pid;
        if (validateIdentity(vendor, init, monitor, received)) {
          close(received[0]);
          close(received[1]);
          failed = 1;
          break;
        }
        vendorfd = received[0];
        close(received[1]);
        armed = 1;
        if (sendRecord(socket, r, ARMED, init, vendor, 0, 0)) {
          failed = 1;
          break;
        }
      } else if (armed && !committed && m.stage == COMMIT) {
        committed = 1;
      } else if (committed && m.stage == CANCEL &&
                 (m.value == 1 || m.value == 2 || m.value == 15)) {
        signalPid(vendorfd, m.value);
        if (!cancel)
          cancel = now() + GRACE;
      } else {
        failed = 1;
        break;
      }
    }
    if (!alive(monitorfd)) {
      int s;
      if (waitpid(monitor, &s, 1) == monitor) {
        result = (s & 127) ? 128 + (s & 127) : (s >> 8) & 255;
      }
      if (!committed)
        result = 78;
      break;
    }
    poll(0, 0, 5);
  }
  if (failed) {
    if (!committed)
      fail(socket, r, 34);
    result = committed ? 137 : 78;
  }
  cleanup(r, getpid(), init, initfd, monitorfd, monitor, &result);
  if (!committed)
    result = 78;
  sendRecord(socket, r, COMPLETE, result, init, 0, 0);
  return result;
}
int sandboxInternal(int isGuardian) {
  struct record r;
  if (readRecord(3, &r))
    return 78;
  return isGuardian ? guardian(&r) : helper(&r);
}
static int registerDaemon(struct record *, int *, int, int, long, int);
int sandboxOuter(char *data, unsigned int length) {
  struct record r;
  if (parse(data, length, &r))
    return 78;
#ifdef SBX_TESTING
  testSuppressAdoption = r.ntests == 6 && !strcmp(r.tests[4], "1");
#endif
  int signal = signals();
  if (syscall(NR_TID) != getpid() || getpid() != r.outer || signal < 0 ||
      prctl(36, 1, 0, 0, 0))
    return failEmpty(-1, &r, 0);
  if (fault(&r, "stale_identity"))
    r.callerStart = "0";
  int caller = checkOwner(r.caller, r.callerStart);
  if (caller < 0)
    return failEmpty(-1, &r, 0);
  if (syscall(436, 3, ~0U, 4))
    return failEmpty(-1, &r, 0);
  int policy = sealed(data, length), control[2], helperControl[2];
  if (policy < 0 || pair(control) || pair(helperControl))
    return failEmpty(-1, &r, 0);
  int argc = 0;
  usize bytes = 0;
  for (int i = 1; i < r.nbwrap; i++)
    bytes += strlen(r.bwrap[i]) + 1;
  /* The public argv is separate from the sealed bubblewrap arguments. */
  char *block = malloc(bytes);
  if (!block)
    return failEmpty(-1, &r, 0);
  for (int i = 1; i < r.nbwrap; i++) {
    usize n = strlen(r.bwrap[i]) + 1;
    memcpy(block + argc, r.bwrap[i], n);
    argc += n;
  }
  int argfd = sealed(block, argc);
  free(block);
  if (argfd < 0)
    return failEmpty(-1, &r, 0);
  char **argv = malloc((r.nself + 2) * sizeof(char *));
  if (!argv)
    return failEmpty(-1, &r, 0);
  for (int i = 0; i < r.nself; i++)
    argv[i] = r.self[i];
  argv[r.nself] = "--sandbox-guardian";
  argv[r.nself + 1] = 0;
  int leaseLock = sandboxLeaseLock(r.lease, 1);
  if (leaseLock < 0)
    return failEmpty(-1, &r, 0);
  int inherited[5] = {policy, control[1], helperControl[1], argfd, leaseLock};
  if (lease(&r, 0, 0, 0))
    return failEmpty(-1, &r, 0);
  int daemonSocket = -1;
  if (*r.control) {
    daemonSocket = registerDaemon(&r, 0, 0, r.outer, now() + DEADLINE, -1);
    if (daemonSocket < 0) {
      lease(&r, 0, 0, 1);
      return failEmpty(-1, &r, 0);
    }
  }
  if (fault(&r, "pre_guardian_crash"))
    die(78);
  int guard = spawn(argv, inherited, 5);
  close(leaseLock);
  close(control[1]);
  close(helperControl[1]);
  close(policy);
  close(argfd);
  if (guard < 0) {
    lease(&r, 0, 0, 1);
    return 78;
  }
  int guardfd = pidfd(guard), monitorfd = -1, initfd = -1, vendorfd = -1,
      monitor = 0, init = 0, vendor = 0;
  int tracked = 0, identified = 0, enforced = 0, armed = 0, committed = 0,
      complete = 0, result = 78, failed = 0, execClosed = 0;
  long setup = now() + DEADLINE, cancel = 0;
  if (guardfd < 0)
    failed = 1;
  while (!failed && (!complete || !execClosed)) {
    if (!complete && !alive(guardfd)) {
      struct pollfd queued = {control[0], 1, 0};
      int queuedResult = poll(&queued, 1, 0);
      if (queuedResult < 0 && ERR == 4)
        continue;
      if (queuedResult <= 0) {
        failed = 1;
        break;
      }
    }
    int sig = pollSignal(signal);
    if (!alive(caller) && !cancel)
      sig = 15;
    if (sig) {
      if (!committed) {
        failed = 1;
        break;
      }
      sendRecord(control[0], &r, CANCEL, sig, 0, 0, 0);
      if (!cancel)
        cancel = now() + GRACE;
    }
    if (!committed && now() >= setup) {
      failed = 1;
      break;
    }
    if (cancel && now() > cancel + REAP && !alive(guardfd)) {
      failed = 1;
      break;
    }
    struct pollfd p[2] = {{control[0], 1, 0},
                          {execClosed ? -1 : helperControl[0], 1, 0}};
    poll(p, 2, 10);
    if (p[0].revents) {
      struct message m;
      struct cred c;
      int fds[2];
      int got = receive(control[0], &r, &m, fds, tracked ? 0 : 2, &c);
      if (got == 0)
        continue;
      if (got != 1 || c.pid != guard) {
        failed = 1;
        break;
      }
      if (!tracked && m.stage == TRACK) {
        monitor = m.pid;
        init = m.value;
        monitorfd = fds[0];
        initfd = fds[1];
        int parent;
        char start[32];
        if (identity(monitor, &parent, start) || parent != guard ||
            fdIdentity(monitorfd, monitor, 0) || fdIdentity(initfd, init, 1)) {
          failed = 1;
          break;
        }
        tracked = 1;
      } else if (enforced && !armed && m.stage == ARMED && m.pid == vendor &&
                 m.value == init) {
        armed = 1;
        if (*r.control) {
          int retained[3] = {monitorfd, vendorfd, initfd};
          daemonSocket = registerDaemon(&r, retained, monitor, vendor, setup,
                                        daemonSocket);
          if (daemonSocket < 0) {
            failed = 1;
            break;
          }
        }
        if (sendRecord(control[0], &r, COMMIT, 0, 0, 0, 0) ||
            sendRecord(helperControl[0], &r, COMMIT, 0, 0, 0, 0)) {
          failed = 1;
          break;
        }
        committed = 1;
      } else if (committed && m.stage == COMPLETE) {
        complete = 1;
        result = m.value;
      } else {
        failed = 1;
        break;
      }
    }
    if (tracked && p[1].revents && !committed) {
      struct message m;
      struct cred c;
      int fds[2];
      int got = receive(helperControl[0], &r, &m, fds, identified ? 0 : 2, &c);
      if (got == 0)
        continue;
      if (got != 1) {
        failed = 1;
        break;
      }
      if (!identified && m.stage == IDENTITY &&
          !validateIdentity(c.pid, init, monitor, fds)) {
        identified = 1;
        vendor = c.pid;
        vendorfd = fds[0];
        close(fds[1]);
        if (sendRecord(helperControl[0], &r, IDENTITY_OK, 0, 0, 0, 0)) {
          failed = 1;
          break;
        }
      } else if (identified && !enforced && c.pid == vendor &&
                 m.stage == ENFORCED && m.value >= 1) {
        enforced = 1;
        int registration[2] = {vendorfd, initfd};
        if (sendRecord(control[0], &r, REGISTER, init, vendor, registration,
                       2)) {
          failed = 1;
          break;
        }
      } else {
        failed = 1;
        break;
      }
    }
    if (committed && !execClosed && p[1].revents) {
      char peek;
      long available = recv(helperControl[0], &peek, 1, 2 | 0x40);
      if (available == 0) {
        execClosed = 1;
      } else if (available > 0) {
        struct message m;
        struct cred c;
        int got = receive(helperControl[0], &r, &m, 0, 0, &c);
        if (got == 0)
          continue;
        if (got != 1 || c.pid != vendor || m.stage != EXEC_ERROR ||
            m.value != 127 ||
            (daemonSocket >= 0 &&
             sendRecord(daemonSocket, &r, EXEC_ERROR, 127, vendor, 0, 0))) {
          failed = 1;
          break;
        }
        execClosed = 1;
      } else if (ERR != 11 && ERR != 4) {
        failed = 1;
        break;
      }
    }
  }
  close(helperControl[0]);
  close(control[0]);
  if (failed) {
    const char *s = "SANDBOX_UNAVAILABLE: SETUP_OR_LIFECYCLE_FAILED\n";
    fullWrite(2, s, strlen(s));
    if (initfd >= 0)
      signalPid(initfd, 9);
    if (monitorfd >= 0)
      signalPid(monitorfd, 9);
    if (guardfd >= 0)
      signalPid(guardfd, 9);
    result = committed ? 137 : 78;
  }
  int guardResult = -1;
  if (complete) {
    long limit = now() + REAP;
    while (alive(guardfd) && now() < limit)
      poll(0, 0, 5);
    int s;
    if (waitpid(guard, &s, 1) == guard)
      guardResult = (s & 127) ? 128 + (s & 127) : (s >> 8) & 255;
  }
  cleanup(&r, guard, init, failed ? initfd : -1, failed ? monitorfd : -1, guard,
          &guardResult);
  if (daemonSocket >= 0) {
    sendRecord(daemonSocket, &r, COMPLETE, result, init, 0, 0);
    close(daemonSocket);
  }
  if (complete && guardResult != result)
    return committed ? 137 : 78;
  return result;
}
/* The daemon retains these descriptors until the namespace exits. */
struct address {
  unsigned short family;
  char path[108];
};
extern int socket(int, int, int);
extern int bind(int, const void *, unsigned int);
extern int listen(int, int);
extern int connect(int, const void *, unsigned int);
extern int accept4(int, void *, unsigned int *, int);
static int address(struct address *a, const char *name) {
  usize n = strlen(name);
  if (n < 1 || n >= sizeof(a->path) || name[0] != '/')
    return -1;
  memset(a, 0, sizeof(*a));
  a->family = 1;
  memcpy(a->path, name, n);
  return (int)n + 3;
}
static int registerDaemon(struct record *r, int *fds, int monitor, int vendor,
                          long limit, int connection) {
  struct address a;
  int n = address(&a, r->control);
  if (n < 0)
    return -1;
  int fd = connection >= 0 ? connection : socket(1, 5 | CLOEXEC | NONBLOCK, 0);
  if (fd < 0)
    return -1;
  int yes = 1;
  if ((connection < 0 &&
       (setsockopt(fd, 1, 16, &yes, 4) || connect(fd, &a, n))) ||
      sendRecord(fd, r, fds ? REGISTER : TRACK, monitor, vendor, fds,
                 fds ? 3 : 0)) {
    close(fd);
    return -1;
  }
  while (now() < limit) {
    struct message m;
    struct cred c;
    int got = receive(fd, r, &m, 0, 0, &c);
    if (got == 1) {
      if (m.stage == (fds ? COMMIT : IDENTITY_OK) && c.pid == r->caller)
        return fd;
      break;
    }
    if (got < 0)
      break;
    struct pollfd p = {fd, 1, 0};
    poll(&p, 1, 10);
  }
  close(fd);
  return -1;
}
int sandboxListen(const char *name) {
  struct address a;
  int n = address(&a, name);
  if (n < 0)
    return -1;
  int fd = socket(1, 5 | CLOEXEC | NONBLOCK, 0);
  if (fd < 0)
    return -1;
  if (bind(fd, &a, n) || listen(fd, 1)) {
    close(fd);
    return -1;
  }
  return fd;
}
int sandboxAccept(int listener) {
  int fd = accept4(listener, 0, 0, CLOEXEC | NONBLOCK);
  if (fd < 0)
    return ERR == 11 ? -2 : -1;
  struct cred peer;
  unsigned int length = sizeof(peer);
  int parent;
  char start[32];
  if (getsockopt(fd, 1, 17, &peer, &length) || length != sizeof(peer) ||
      peer.uid != getuid() || identity(peer.pid, &parent, start) ||
      parent != getpid()) {
    close(fd);
    return -2;
  }
  int yes = 1;
  if (setsockopt(fd, 1, 16, &yes, 4)) {
    close(fd);
    return -1;
  }
  return fd;
}
int sandboxRegister(int socket, int *out, char *ownership, int cancelled) {
  struct message peek;
  long n = recv(socket, &peek, sizeof(peek), 2 | 0x40);
  if (n < 0 && (ERR == 11 || ERR == 4))
    return 0;
  if (n != sizeof(peek) || peek.id[64] || peek.digest[64])
    return -1;
  struct record r;
  memset(&r, 0, sizeof(r));
  r.id = peek.id;
  r.digest = peek.digest;
  struct message m;
  struct cred c;
  int fds[3];
  int got = receive(socket, &r, &m, fds, peek.stage == TRACK ? 0 : 3, &c);
  if (got != 1)
    return got;
  int parent;
  char start[32];
  if (m.stage == TRACK) {
    if (identity(c.pid, &parent, start) || parent != getpid() ||
        m.pid != c.pid || m.lease[4095] || m.lease[0] != '/')
      return -1;
    int owner = checkOwner(c.pid, start);
    if (owner < 0)
      return -1;
    out[0] = c.pid;
    out[7] = owner;
    memcpy(ownership, m.lease, 4096);
    memcpy(ownership + 4096, m.id, 65);
    if (sendRecord(socket, &r, cancelled ? CANCEL : IDENTITY_OK, 0, 0, 0, 0)) {
      close(owner);
      return -1;
    }
    return 2;
  }
  int monitor = m.value, vendor = m.pid, init = -1;
  char path[80], buf[4096];
  snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fds[2]);
  if (textFile(path, buf, sizeof(buf)) >= 0) {
    char *p = strstr(buf, "Pid:\t");
    if (p)
      sscanf(p, "Pid:\t%d", &init);
  }
  if (m.stage != REGISTER || identity(c.pid, &parent, start) ||
      parent != getpid() || out[0] != c.pid || strcmp(m.id, ownership + 4096) ||
      fdIdentity(fds[0], monitor, 0) ||
      validateIdentity(vendor, init, monitor, &fds[1])) {
    for (int i = 0; i < 3; i++)
      close(fds[i]);
    return -1;
  }
  out[0] = c.pid;
  out[1] = fds[0];
  out[2] = fds[1];
  out[3] = fds[2];
  out[4] = monitor;
  out[5] = vendor;
  out[6] = init;
  if (m.lease[4095] || m.lease[0] != '/') {
    for (int i = 0; i < 3; i++)
      close(fds[i]);
    return -1;
  }
  memcpy(ownership, m.lease, 4096);
  memcpy(ownership + 4096, m.id, 65);
  if (cancelled || sendRecord(socket, &r, COMMIT, 0, 0, 0, 0)) {
    for (int i = 0; i < 3; i++)
      close(fds[i]);
    return -1;
  }
  return 1;
}
int sandboxDescriptorsExited(int *fds) {
  return !alive(fds[0]) && !alive(fds[1]) && !alive(fds[2]);
}
int sandboxSignal(int fd, int value) { return signalPid(fd, value); }
int sandboxClose(int fd) { return close(fd); }
int sandboxCompletion(int socket, int outer, int *status) {
  struct message peek;
  long n = recv(socket, &peek, sizeof(peek), 2 | 0x40);
  if (n < 0 && (ERR == 11 || ERR == 4))
    return 0;
  if (n != sizeof(peek) || peek.id[64] || peek.digest[64])
    return -1;
  struct record r;
  memset(&r, 0, sizeof(r));
  r.id = peek.id;
  r.digest = peek.digest;
  struct message m;
  struct cred c;
  int got = receive(socket, &r, &m, 0, 0, &c);
  if (got == 0)
    return 0;
  if (got != 1 || c.pid != outer)
    return -1;
  if (m.stage == COMPLETE && m.value >= 0 && m.value <= 255) {
    *status = m.value;
    return 1;
  }
  return m.stage == EXEC_ERROR && m.value == 127 ? 2 : -1;
}

/* Wait off the JavaScript thread. Closing the stream cancels this wait. */
extern int pthread_create(unsigned long *, const void *, void *(*)(void *), void *);
extern int pthread_detach(unsigned long);
extern long send(int, const void *, usize, int);
extern int shutdown(int, int);
struct readiness {
  struct pollfd fds[6];
  int count;
  int timeout;
};
static void *waitReady(void *data) {
  struct readiness *w = data;
  long limit = w->timeout < 0 ? -1 : now() + w->timeout;
  int rc;
  do {
    int remaining = limit < 0 ? -1 : (int)(limit - now());
    rc = poll(w->fds, w->count, limit >= 0 && remaining < 0 ? 0 : remaining);
  } while (rc < 0 && ERR == 4);
  for (int i = 1; i < w->count; i++)
    close(w->fds[i].fd);
  send(w->fds[0].fd, "r", 1, 0x4000);
  close(w->fds[0].fd);
  free(w);
  return 0;
}
int sandboxWatch(int *fds, int count, int timeout) {
  if (count < 0 || count > 5 || timeout < -1)
    return -1;
  struct readiness *w = malloc(sizeof(*w));
  if (!w)
    return -1;
  int channel[2];
  if (socketpair(1, 1 | CLOEXEC, 0, channel)) {
    free(w);
    return -1;
  }
  memset(w, 0, sizeof(*w));
  w->fds[0].fd = channel[1];
  w->fds[0].events = 1;
  w->count = 1;
  w->timeout = timeout;
  for (int i = 0; i < count; i++) {
    int fd = fcntl(fds[i], 1030, 3);
    if (fd < 0)
      goto failed;
    w->fds[w->count].fd = fd;
    w->fds[w->count++].events = 1;
  }
  unsigned long thread;
  if (pthread_create(&thread, 0, waitReady, w))
    goto failed;
  pthread_detach(thread);
  return channel[0];
failed:
  for (int i = 0; i < w->count; i++)
    close(w->fds[i].fd);
  close(channel[0]);
  free(w);
  return -1;
}
int sandboxAlive(int fd) { return alive(fd); }
int sandboxWatchCancel(int fd) { return shutdown(fd, 2); }
