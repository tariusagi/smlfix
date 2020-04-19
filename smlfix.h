#ifndef _SMLFIX_H
#define _SMLFIX_H

#define DLL_NAME			"C:\\Windows\\smlfix.dll"
#define SHARED_MEM_NAME		"smlfixshm"
#define MUTEX_NAME			"smlfixmutex"
#define SECONDARY_HOST		"C:\\Windows\\system32\\csrss.exe"

typedef enum {
	ACTION_IGNORE,
	ACTION_LOGOFF,
	ACTION_REBOOT,
	ACTION_REBOOT2,
	ACTION_SHUTDOWN
} action_t;

typedef struct
{
	BOOL		verbose;
	BOOL		disable_logging;
	char		log_path[MAX_PATH];
	// Countdown number before taking action.
	int			countdown;
	// Action to take when Sml is attacked.
	action_t	watchdog_action;
	// Full path to Sml installed folder.
	char		sml_path[MAX_PATH];
	// Set this to TRUE to unload the watchdog.
	BOOL		unload;
} shared_mem_t;

extern BOOL verbose_flag;
extern BOOL log_flag;
extern char log_path[MAX_PATH];

void trim(char *s);
void log_text(char* format, ...);
void log_error(DWORD err_no, char* format, ...);
void force_reboot(int action);
void reboot_using_shutdown_cmd();
BOOL set_debug_priv();
BOOL get_ip(char **ip);
BOOL get_ipv4_bytes(unsigned char *b1, unsigned char *b2, unsigned char *b3, unsigned char *b4);
DWORD get_pid_from_path(LPCSTR szPath, DWORD session_id);
DWORD GetPidFromPath(LPCSTR szPath);
DWORD inject_dll(DWORD pid, const char *name);
BOOL resume_process(DWORD pid);

#endif
