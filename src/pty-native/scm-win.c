/*
 * Windows SCM handshake shim for the in-process OpenLLM daemon service.
 *
 * Freestanding like pty-win.c: zero #include directives; kernel32/advapi32
 * symbols are extern declarations. TinyCC on the win32 guest links advapi32
 * for SetServiceStatus / StartServiceCtrlDispatcherW.
 *
 * Target: win32-x64 only (PTY_WINDOWS gate matches the ConPTY shim discipline).
 */

#if defined(PTY_WINDOWS)
#if !defined(_WIN32) || !defined(_WIN64)
#error "PTY_WINDOWS does not match the compiler target (need win32-x64)"
#endif
#else
#error "scm-win.c supports only PTY_WINDOWS (win32-x64)"
#endif

typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef void *scm_handle_t;

typedef int32_t BOOL;
typedef uint32_t DWORD;

#define WINAPI

typedef scm_handle_t SERVICE_STATUS_HANDLE;

typedef struct {
  uint32_t dwServiceType;
  uint32_t dwCurrentState;
  uint32_t dwControlsAccepted;
  uint32_t dwWin32ExitCode;
  uint32_t dwServiceSpecificExitCode;
  uint32_t dwCheckPoint;
  uint32_t dwWaitHint;
} SERVICE_STATUS;

typedef struct {
  const uint16_t *lpServiceName;
  void (WINAPI *lpServiceMain)(uint32_t dwArgc, uint16_t **lpszArgv);
} SERVICE_TABLE_ENTRYW;

#define SERVICE_WIN32_OWN_PROCESS 0x00000010U
#define SERVICE_STOPPED 0x00000001U
#define SERVICE_START_PENDING 0x00000002U
#define SERVICE_STOP_PENDING 0x00000003U
#define SERVICE_RUNNING 0x00000004U

#define SERVICE_CONTROL_STOP 0x00000001U
#define SERVICE_CONTROL_SHUTDOWN 0x00000005U
#define SERVICE_CONTROL_INTERROGATE 0x00000004U

#define SERVICE_ACCEPT_STOP 0x00000001U
#define SERVICE_ACCEPT_SHUTDOWN 0x00000002U

#define NO_ERROR 0U
#define ERROR_FAILED_SERVICE_CONTROLLER_CONNECT 1063U

#define SCM_START_WAIT_MS 120000U
#define SCM_POLL_MS 50U

extern BOOL StartServiceCtrlDispatcherW(const SERVICE_TABLE_ENTRYW *lpServiceStartTable);
extern SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerW(
    const uint16_t *lpServiceName,
    DWORD (WINAPI *lpHandler)(DWORD dwControl));
extern BOOL SetServiceStatus(SERVICE_STATUS_HANDLE hServiceStatus, SERVICE_STATUS *lpServiceStatus);
extern DWORD GetLastError(void);
extern void Sleep(DWORD dwMilliseconds);

static const uint16_t SCM_SERVICE_NAME[] = {
    'O', 'p', 'e', 'n', 'L', 'L', 'M', 'D', 0,
};

static SERVICE_STATUS g_status;
static SERVICE_STATUS_HANDLE g_status_handle;
static volatile uint32_t g_running_reported;
static volatile uint32_t g_start_failed;
static volatile uint32_t g_stop_requested;
static volatile uint32_t g_stopped_reported;
static volatile uint32_t g_exit_code;
static volatile uint32_t g_stop_callback_pending;

static void (*g_on_start)(void);
static void (*g_on_stop)(void);

static void scm_set_status(uint32_t state, uint32_t controls, uint32_t exit_code, uint32_t checkpoint,
                           uint32_t wait_hint) {
  g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_status.dwCurrentState = state;
  g_status.dwControlsAccepted = controls;
  g_status.dwWin32ExitCode = exit_code;
  g_status.dwServiceSpecificExitCode = 0;
  g_status.dwCheckPoint = checkpoint;
  g_status.dwWaitHint = wait_hint;
  if (g_status_handle != (SERVICE_STATUS_HANDLE)0) {
    SetServiceStatus(g_status_handle, &g_status);
  }
}

static DWORD WINAPI scm_control_handler(DWORD dwControl) {
  if (dwControl == SERVICE_CONTROL_INTERROGATE) {
    scm_set_status(g_status.dwCurrentState, g_status.dwControlsAccepted, g_status.dwWin32ExitCode,
                   g_status.dwCheckPoint, g_status.dwWaitHint);
    return NO_ERROR;
  }
  if (dwControl != SERVICE_CONTROL_STOP && dwControl != SERVICE_CONTROL_SHUTDOWN) {
    return NO_ERROR;
  }
  if (g_stop_requested) {
    return NO_ERROR;
  }
  g_stop_requested = 1U;
  scm_set_status(SERVICE_STOP_PENDING, 0U, NO_ERROR, g_status.dwCheckPoint + 1U, 15000U);
  g_stop_callback_pending = 1U;
  return NO_ERROR;
}

static void scm_poll_stop_callback(void) {
  if (g_stop_callback_pending && g_on_stop != (void (*)(void))0) {
    g_stop_callback_pending = 0U;
    g_on_stop();
  }
}

static void scm_wait_until(volatile uint32_t *flag, uint32_t timeout_ms) {
  uint32_t elapsed = 0U;
  while (*flag == 0U) {
    scm_poll_stop_callback();
    if (timeout_ms != 0xFFFFFFFFU && elapsed >= timeout_ms) {
      break;
    }
    Sleep(SCM_POLL_MS);
    if (timeout_ms != 0xFFFFFFFFU) {
      elapsed += SCM_POLL_MS;
    }
  }
}

static void WINAPI scm_service_main(uint32_t dwArgc, uint16_t **lpszArgv) {
  (void)dwArgc;
  (void)lpszArgv;

  g_status_handle = RegisterServiceCtrlHandlerW(SCM_SERVICE_NAME, scm_control_handler);
  if (g_status_handle == (SERVICE_STATUS_HANDLE)0) {
    return;
  }

  g_running_reported = 0U;
  g_start_failed = 0U;
  g_stop_requested = 0U;
  g_stopped_reported = 0U;
  g_exit_code = 1U;
  g_stop_callback_pending = 0U;

  scm_set_status(SERVICE_START_PENDING, 0U, NO_ERROR, 1U, 3000U);

  if (g_on_start != (void (*)(void))0) {
    g_on_start();
  }

  scm_wait_until(&g_running_reported, SCM_START_WAIT_MS);
  if (g_start_failed) {
    scm_set_status(SERVICE_STOPPED, 0U, g_exit_code, 0U, 0U);
    return;
  }
  if (!g_running_reported) {
    scm_set_status(SERVICE_STOPPED, 0U, 1063U, 0U, 0U);
    return;
  }

  scm_wait_until(&g_stopped_reported, 0xFFFFFFFFU);
  scm_set_status(SERVICE_STOPPED, 0U, g_exit_code, 0U, 0U);
}

static SERVICE_TABLE_ENTRYW g_service_table[2];

int32_t scmAbiVersion(void) { return 1; }

uint32_t scmErrorNotServiceController(void) { return ERROR_FAILED_SERVICE_CONTROLLER_CONNECT; }

void scmBindCallbacks(void (*on_start)(void), void (*on_stop)(void)) {
  g_on_start = on_start;
  g_on_stop = on_stop;
}

int32_t scmDispatch(void) {
  g_service_table[0].lpServiceName = SCM_SERVICE_NAME;
  g_service_table[0].lpServiceMain = scm_service_main;
  g_service_table[1].lpServiceName = (const uint16_t *)0;
  g_service_table[1].lpServiceMain = (void (WINAPI *)(uint32_t, uint16_t **))0;

  if (!StartServiceCtrlDispatcherW(g_service_table)) {
    return (int32_t)GetLastError();
  }
  return 0;
}

void scmReportRunning(void) {
  g_running_reported = 1U;
  scm_set_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, NO_ERROR, 0U, 0U);
}

void scmReportStartFailed(uint32_t exit_code) {
  g_exit_code = exit_code;
  g_start_failed = 1U;
}

void scmReportStopped(uint32_t exit_code) {
  g_exit_code = exit_code;
  g_stopped_reported = 1U;
}
