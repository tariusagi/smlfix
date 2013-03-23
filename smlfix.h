#ifndef _SMLFIX_H
#define _SMLFIX_H

#define DLL_NAME			"C:\\Windows\\system32\\smlfix.dll"
#define SHARED_MEM_NAME		"smlfixshm"
#define MUTEX_NAME			"smlfixmutex"
#define SECONDARY_HOST		"C:\\Windows\\system32\\csrss.exe"

typedef enum {
	ACTION_IGNORE,
	ACTION_LOGOFF,
	ACTION_REBOOT,
	ACTION_HARD_REBOOT,
	ACTION_SHUTDOWN
} action_t;

typedef struct
{
	BOOL		verbose;
	BOOL		disable_logging;
	char		log_path[_MAX_PATH];
	// Countdown number before taking action.
	int			countdown;
	// Action to take when Sml is attacked.
	action_t	watchdog_action;
	// Full path to Sml installed folder.
	char		sml_path[_MAX_PATH];
	// Set this to TRUE to unload the watchdog.
	BOOL		unload;
} shared_mem_t;

extern BOOL verbose_flag;
extern BOOL log_flag;
extern char log_path[_MAX_PATH];

void trim(char *s);
void yell(char* format, ...);
void do_log(char* format, ...);
void do_error_log(DWORD err_no, char* format, ...);
void force_reboot(int action);
BOOL set_debug_priv();
BOOL get_ip(char **ip);
DWORD get_pid_from_path(LPCSTR szPath, DWORD session_id);
DWORD GetPidFromPath(LPCSTR szPath);
DWORD inject_dll(DWORD pid, const char *name);
BOOL resume_process(DWORD pid);

#endif
