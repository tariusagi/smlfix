#define _WIN32_WINDOWS 0x4100
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <process.h>
#include "smlfix.h"

// Some definitions from Windows NT DDK and other sources.
#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemProcessesAndThreadsInformation	5

typedef LONG	NTSTATUS;
typedef LONG	KPRIORITY;

typedef struct _CLIENT_ID {
	DWORD	    UniqueProcess;
	DWORD	    UniqueThread;
} CLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT	    Length;
	USHORT	    MaximumLength;
	PWSTR	    Buffer;
} UNICODE_STRING;

typedef struct _VM_COUNTERS {
	SIZE_T	    PeakVirtualSize;
	SIZE_T	    VirtualSize;
	ULONG	    PageFaultCount;
	SIZE_T	    PeakWorkingSetSize;
	SIZE_T	    WorkingSetSize;
	SIZE_T	    QuotaPeakPagedPoolUsage;
	SIZE_T	    QuotaPagedPoolUsage;
	SIZE_T	    QuotaPeakNonPagedPoolUsage;
	SIZE_T	    QuotaNonPagedPoolUsage;
	SIZE_T	    PagefileUsage;
	SIZE_T	    PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER   KernelTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   CreateTime;
	ULONG			WaitTime;
	PVOID			StartAddress;
	CLIENT_ID	    ClientId;
	KPRIORITY	    Priority;
	KPRIORITY	    BasePriority;
	ULONG			ContextSwitchCount;
	LONG			State;
	LONG			WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;

// NOTE: SYSTEM_PROCESSES structure is different on NT 4 and Win2K
typedef struct _SYSTEM_PROCESSES {
	ULONG			NextEntryDelta;
	ULONG			ThreadCount;
	ULONG			Reserved1[6];
	LARGE_INTEGER   CreateTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   KernelTime;
	UNICODE_STRING  ProcessName;
	KPRIORITY	    BasePriority;
	ULONG			ProcessId;
	ULONG			InheritedFromProcessId;
	ULONG			HandleCount;
	ULONG			Reserved2[2];
	VM_COUNTERS	    VmCounters;
#if _WIN32_WINNT >= 0x500
	IO_COUNTERS	    IoCounters;
#endif
	SYSTEM_THREADS  Threads[1];
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef LONG (WINAPI *ZWQUERYSYSTEMINFORMATION)(UINT SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

BOOL verbose_flag = FALSE;
BOOL log_flag = FALSE;
char log_path[_MAX_PATH] = "";

// Print a text to the log file (if logging is on) and STDOUT (if verbose).
// NOTE: the output log text is limitted at 500 characters.
void log_text(char* format, ...)
{
	char					timestamp[9];
	char					text[501];
	time_t					t;
	FILE*					f;
	va_list					argList;

	// If both logging and verbose is off, then there's nothing to do.
	if (!(log_flag || verbose_flag))
		return;

	// Format the current timestamp.
	t = time(NULL);
	strftime(timestamp, 9, "%H:%M:%S", (const struct tm *)localtime(&t));

	// Build the text from input arguments.
	va_start(argList, format);
	vsnprintf(text, 500, format, argList);
	va_end(argList);

	// Now if logging is on and the path to log file is set..
	if (log_flag && strlen(log_path))
	{
		// ..create/open the log file and write log content.
		if ((f = fopen(log_path, "a+")) != NULL)
		{
			fprintf(f, "%s - %s\n", timestamp, text);
			fclose(f);
		}
	}

	// And if verbose is on, then print the text to STDOUT, too.
	if (verbose_flag)
		printf("%s - %s\n", timestamp, text);
}

// Output a formatted log text along with the latest system error string for the
// given system error code (in errno).
void log_error(DWORD err_no, char* format, ...)
{
	char					timestamp[9];
	char					text[501];
	time_t					t;
	FILE*					f;
	va_list					argList;
	LPVOID					sys_msg_buf = NULL;

	// If both logging and verbose is off, then there's nothing to do.
	if (!(log_flag || verbose_flag))
		return;

	// Format the current timestamp.
	t = time(NULL);
	strftime(timestamp, 9, "%H:%M:%S", (const struct tm *)localtime(&t));

	// Build the text from input arguments.
	va_start(argList, format);
	vsnprintf(text, 500, format, argList);
	va_end(argList);

	// Get the system error string if err_no is not zero.
	if (err_no)
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
				  FORMAT_MESSAGE_FROM_SYSTEM | 
				  FORMAT_MESSAGE_IGNORE_INSERTS,
				  NULL, 
				  err_no, 
				  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				  (LPTSTR) &sys_msg_buf, 
				  0, 
				  NULL);

	// Now if logging is on and the path to log file is set..
	if (log_flag && strlen(log_path))
	{
		// ..create/open the log file and write log content.
		if ((f = fopen(log_path, "a+")) != NULL)
		{
			if (sys_msg_buf == NULL)
				fprintf(f, "%s - ERROR: %s\n", timestamp, text);
			else
				fprintf(f, "%s - ERROR: %s. %s\n", timestamp, text, (char *) sys_msg_buf);
			fclose(f);
		}
	}

	// And if verbose is on, then print the text to STDERR, too.
	if (verbose_flag)
	{
		if (sys_msg_buf == NULL)
			fprintf(stderr, "%s - ERROR: %s\n", timestamp, text);
		else
			fprintf(stderr, "%s - ERROR: %s. %s\n", timestamp, text, (char *) sys_msg_buf);
	}

	// Free the system message buffer if it's allocated.
	if (sys_msg_buf != NULL)
		LocalFree(sys_msg_buf);
}

void trim(char *s)
{
	char *t;
	int i;
	if (s != NULL && strlen(s))
	{
		t = (char *)malloc(strlen(s) + 1);
		strcpy(t, s);
		while (*t && (*t == ' ' || *t == '\t' || *t == '\r' || *t == '\n'))
			t++;
		if (strlen(t))
		{
			strcpy(s, t);
			i = strlen(s) - 1;
			while (i && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n'))
				s[i--] = 0;
		}
		else
			s[0] = 0;
		free(t);
	}
}

// Retrieve current IPv4 into a string.
BOOL get_ip(char **ip)
{
	WORD winsock_version = MAKEWORD(2,0);
	WSADATA winsock_data;
	char host_name[65];
	LPHOSTENT host_info;

	if (WSAStartup(winsock_version, &winsock_data) != 0)
	{
		log_error(GetLastError(), "Failed to initialize Winsock 2 library");
		return FALSE;
	}

	if (gethostname(host_name, sizeof(host_name) - 1) != 0)
	{
		log_error(GetLastError(), "Failed to query local hostname");
		WSACleanup();
		return FALSE;
	}

	log_text("The current host name: \"%s\".", host_name);
	if ((host_info = gethostbyname(host_name)) == NULL)
	{
		log_error(GetLastError(), "Failed to query host info");
		WSACleanup();
		return FALSE;
	} 

	*ip = inet_ntoa(*((struct in_addr *)host_info->h_addr_list[0]));
	log_text("The current IP: %s.", *ip);
	WSACleanup();
	return TRUE;
}

// Retrieve current IPv4 into 4 bytes.
BOOL get_ipv4_bytes(unsigned char *b1, unsigned char *b2, unsigned char *b3, unsigned char *b4)
{
	WORD winsock_version = MAKEWORD(2,0);
	WSADATA winsock_data;
	char host_name[65];
	LPHOSTENT host_info;

	if (WSAStartup(winsock_version, &winsock_data) != 0)
	{
		log_error(GetLastError(), "Failed to initialize Winsock 2 library");
		return FALSE;
	}

	if (gethostname(host_name, sizeof(host_name) - 1) != 0)
	{
		log_error(GetLastError(), "Failed to query local hostname");
		WSACleanup();
		return FALSE;
	}

	log_text("The current host name: \"%s\".", host_name);
	if ((host_info = gethostbyname(host_name)) == NULL)
	{
		log_error(GetLastError(), "Failed to query host info");
		WSACleanup();
		return FALSE;
	} 
	
	*b1 = ((struct in_addr *)host_info->h_addr_list[0])->S_un.S_un_b.s_b1;
	*b2 = ((struct in_addr *)host_info->h_addr_list[0])->S_un.S_un_b.s_b2;
	*b3 = ((struct in_addr *)host_info->h_addr_list[0])->S_un.S_un_b.s_b3;
	*b4 = ((struct in_addr *)host_info->h_addr_list[0])->S_un.S_un_b.s_b4;

	log_text("The current IP: %d.%d.%d.%d", *b1, *b2, *b3, *b4);
	WSACleanup();
	return TRUE;
}

DWORD inject_dll(DWORD pid, const char *name)
{
	HANDLE proccess_handle, thread_handle, token_handle;
	LPVOID dll_name, load_lib_address;
	TOKEN_PRIVILEGES token_privilege; 
	DWORD ret_val;

	// Adjust privelege token so this process can inject DLL.
	// Open this process' token. 
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) 
	{
		log_error(GetLastError(), "Failed to open process token");
		return -1;
	}
	// Get the LUID for the inject DLL (DEBUG) privilege. 
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &token_privilege.Privileges[0].Luid); 
	token_privilege.PrivilegeCount = 1;  // one privilege to set    
	token_privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	// Get the shutdown privilege for this process. 
	AdjustTokenPrivileges(token_handle, FALSE, &token_privilege, 0, (PTOKEN_PRIVILEGES)NULL, 0); 

	// Cannot test the return value of AdjustTokenPrivileges. 
	if (GetLastError() != ERROR_SUCCESS) 
	{
		log_error(GetLastError(), "Failed to adjust debug privilege");
		return -1;
	}

	proccess_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if(!proccess_handle)
	{
		log_error(GetLastError(), "Couldn't open host process");
		return -1;
	}

	load_lib_address = (LPVOID) GetProcAddress(
			GetModuleHandle("kernel32.dll"),
			"LoadLibraryA");

	if (load_lib_address == NULL)
	{
		log_error(GetLastError(), "Couldn't get LoadLibraryA address");
		return -1;
	}

	dll_name = (LPVOID) VirtualAllocEx(
			proccess_handle,
			NULL,
			strlen(name) + 1,
			MEM_RESERVE|MEM_COMMIT,
			PAGE_READWRITE);

	WriteProcessMemory(
			proccess_handle,
			(LPVOID) dll_name,
			name, 
			strlen(name) + 1,
			NULL);

	thread_handle = CreateRemoteThread(
			proccess_handle,
			NULL,
			0,
			(LPTHREAD_START_ROUTINE) load_lib_address,
			(LPVOID) dll_name,
			0,
			NULL);   

	if (thread_handle == NULL)
	{
		log_error(GetLastError(), "Couldn't create remote thread");
		return -1;
	}
	else
		log_text("Remote thread was created.");

	WaitForSingleObject(thread_handle, INFINITE);
	GetExitCodeThread(thread_handle, &ret_val);

	CloseHandle(thread_handle);
	VirtualFreeEx(proccess_handle, dll_name , strlen(name) + 1, MEM_RELEASE);
	CloseHandle(proccess_handle);

	return ret_val == 0 ? FALSE : TRUE;
} 

// Set DEBUG privilege to the calling process.
// Return TRUE on success, FALSE on failure.
BOOL set_debug_priv()
{
	HANDLE token_handle;
	TOKEN_PRIVILEGES token_privilege; 

	// Open the calling process' token. 
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) 
	{
		log_error(GetLastError(), "Failed to open process token");
		return FALSE;
	}
	// Get the LUID for the inject DLL (DEBUG) privilege. 
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &token_privilege.Privileges[0].Luid); 
	token_privilege.PrivilegeCount = 1;  // one privilege to set    
	token_privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 

	// Set the privilege.
	if (!AdjustTokenPrivileges(token_handle, FALSE, &token_privilege, 0, (PTOKEN_PRIVILEGES)NULL, 0)) 
	{
		log_error(GetLastError(), "Failed to adjust debug privilege");
		return FALSE;
	}
	else return TRUE;
}

void force_reboot(int action)
{
	// Adjust privelege token so this process can shutdown Windows.
	HANDLE token_handle; 
	TOKEN_PRIVILEGES token_privilege; 
	UINT flags = 0;
	// Get a token for this process. 
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) 
	{
		log_error(GetLastError(), "Failed to open process token");
		return;
	}
	// Get the LUID for the shutdown privilege. 
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &token_privilege.Privileges[0].Luid); 
	token_privilege.PrivilegeCount = 1;  // one privilege to set    
	token_privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	// Get the shutdown privilege for this process. 
	AdjustTokenPrivileges(token_handle, FALSE, &token_privilege, 0, (PTOKEN_PRIVILEGES)NULL, 0); 
	// Cannot test the return value of AdjustTokenPrivileges. 
	if (GetLastError() != ERROR_SUCCESS) 
	{
		log_error(GetLastError(), "Failed to adjust shutdown privilege");
		return;
	}
	// Gonna reboot using system's shutdown command?
	if (action == ACTION_REBOOT2)
	{
		reboot_using_shutdown_cmd();
		log_text("Forced a reboot using shutdown.exe.");
	}
	else
	{
		// No. Will shutdown using ExitWindowsEx API.
		// Set the flags.
		switch (action)
		{
			case ACTION_LOGOFF:
				flags = EWX_LOGOFF | EWX_FORCE | EWX_FORCEIFHUNG;
				break;
			case ACTION_REBOOT:
				flags = EWX_REBOOT | EWX_FORCE | EWX_FORCEIFHUNG;
				break;
			case ACTION_SHUTDOWN:
				flags = EWX_POWEROFF | EWX_FORCE | EWX_FORCEIFHUNG;
				break;
		}
		// Reboot the system and force all applications to close. 
		if (!ExitWindowsEx(flags, 0))
			log_error(GetLastError(), "Failed to force a reboot");
		else switch (action)
		{
			case ACTION_LOGOFF:
				log_text("Forced a log off.");
				break;
			case ACTION_REBOOT:
				log_text("Forced a reboot.");
				break;
			case ACTION_SHUTDOWN:
				log_text("Forced a shutdown.");
				break;
		}
	}

	return;
}

// -----------------------------------------------------------------------------
// get_pid_from_path find the process ID (PID) using the given path and
// optional session ID. If the session_id is positive, then only process that
// match the given session ID is returned.
//
// Note that if the given path is not a full path (which has the colon character
// to denote the drive letter) then this routine will use only the file name
// portion. In either case, the first match will be returned.
// -----------------------------------------------------------------------------
DWORD get_pid_from_path(LPCSTR path, DWORD session_id)
{
	DWORD pid = 0;
	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process_entries = {0};
	process_entries.dwSize = sizeof(process_entries);
	BOOL is_full_path = strchr(path, ':') != NULL;
	char file_name[MAX_MODULE_NAME32];
	char short_path[MAX_PATH + 1] = "";

	if (strchr(path, '\\') != NULL)
		strcpy(file_name, (const char *)(strrchr(path, '\\') + 1));
	else
		strcpy(file_name, path);

	if (verbose_flag)
	{
		if (is_full_path)
			log_text("Getting PID from (full path) %s.", path);
		else
			log_text("Getting PID from %s.", file_name);
	}

	GetShortPathNameA(path, short_path, MAX_PATH);

	if (!Process32First(snapshot_handle, &process_entries))
	{
		CloseHandle(snapshot_handle);
		log_error(GetLastError(), "Unable to query processes list");
		return 0;
	}

	do
	{
		if (_stricmp(file_name, process_entries.szExeFile) == 0)
		{
			HANDLE process_handle;

			process_handle = OpenProcess
				( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
				, FALSE
				, process_entries.th32ProcessID);

			if (process_handle != NULL)
			{
				if (is_full_path)
				{
					HMODULE temp[1];
					HMODULE *module_handles;
					DWORD module_enum_size;
					char s[MAX_PATH];
					char *module_path;
					int i;

					if (EnumProcessModules
							( process_handle
							, temp 
							, sizeof(temp)
							, &module_enum_size))
					{
						module_handles = malloc(module_enum_size);
						EnumProcessModules
							( process_handle
							, module_handles 
							, module_enum_size
							, &module_enum_size);

						i = 0;
						while (pid == 0 && i < (module_enum_size / sizeof(HMODULE)))
						{

							if (GetModuleFileNameEx
									( process_handle
									  , module_handles[i]
									  , s
									  , sizeof(s)))
							{
								module_path = strchr(s, ':') - 1;

								if (_stricmp(path, module_path) == 0 ||
									_stricmp(short_path, module_path) == 0)
								{
									pid = process_entries.th32ProcessID;
								}
							}

							i++;
						}
					}
				}
				else pid = process_entries.th32ProcessID;
			}
			else
			{
				CloseHandle(snapshot_handle);
				log_error(GetLastError(), "Couldn't open handle to process ID %d", process_entries.th32ProcessID);
				return 0;
			}

			if (pid) log_text("Found PID %d.", pid);

			if (pid && (session_id != -1))
			{
				// A process that match the given path has been found?
				// We need to check its session.
				DWORD session_id2;

				log_text("Checking session from PID %d against SID %d...", pid, session_id);

				if (!ProcessIdToSessionId(pid, &session_id2))
				{
					log_error(GetLastError(), "Couldn't get session ID from PID %d", process_entries.th32ProcessID);
					CloseHandle(process_handle);
					return 0;
				}

				if (session_id != session_id2)
				{
					pid = 0;
					log_text("PID %d is in session %d, doesn't match SID %d.", pid, session_id2, session_id);
				}
				else
					log_text("PID %d is in session %d, match SID %d.", pid, session_id2, session_id);
			}

			CloseHandle(process_handle);
		}
	}
	while (pid == 0 && Process32Next(snapshot_handle, &process_entries));

	CloseHandle(snapshot_handle);

	return pid;
}

BOOL resume_process(DWORD pid)
{
	HANDLE thread_snap_handle = NULL; 
	BOOL ret_val = FALSE; 
	THREADENTRY32 te32 = {0}; 

	thread_snap_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 

	if (thread_snap_handle == INVALID_HANDLE_VALUE) 
		return FALSE; 

	te32.dwSize = sizeof(THREADENTRY32); 

	if (Thread32First(thread_snap_handle, &te32)) 
	{ 
		do 
		{ 
			if (te32.th32OwnerProcessID == pid) 
			{ 
				HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);

				if (thread_handle != NULL)
				{
					ResumeThread(thread_handle);
					CloseHandle(thread_handle);
				}
			} 
		} 
		while (Thread32Next(thread_snap_handle, &te32)); 

		ret_val = TRUE; 
	} 
	else 
		ret_val = FALSE;

	CloseHandle (thread_snap_handle); 

	return ret_val; 
}

BOOL has_module(DWORD pid, LPCSTR exe_path) 
{ 
    BOOL found = FALSE; 
    HANDLE mod_snap = NULL; 
    MODULEENTRY32 mod_snap_entry = {0}; 
	char full_path[MAX_PATH + 1];

    mod_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid); 

    if (mod_snap == INVALID_HANDLE_VALUE) 
	{
		log_error(GetLastError(), "Couldn't get module snapshot of PID %u", pid);
        return FALSE; 
	}

    mod_snap_entry.dwSize = sizeof(MODULEENTRY32); 

    if (Module32First(mod_snap, &mod_snap_entry)) 
    { 
        do 
        { 
			if (GetLongPathName(mod_snap_entry.szExePath, full_path, sizeof(full_path)))
			{
				log_text("%u has module %s", pid, full_path);

				if (_stricmp(full_path, exe_path) == 0) 
				{
					found = TRUE; 
					break;
				}
			}
        } 
        while (!found && Module32Next(mod_snap, &mod_snap_entry)); 
    } 

    CloseHandle (mod_snap); 

    return (found); 
} 

// Reboot Windows using system's shutdown command:
// shutdown.exe /r /t 0
void reboot_using_shutdown_cmd()
{
	char shutdown_cmd_path[_MAX_PATH];

	GetEnvironmentVariable("Windir", shutdown_cmd_path, _MAX_PATH);
	strcat(shutdown_cmd_path, "\\system32\\shutdown.exe");
	if (_spawnl(_P_NOWAIT, shutdown_cmd_path, shutdown_cmd_path, "/r", "/t", "0", NULL) == (intptr_t) NULL)
		log_text("(MAIN) Couldn't execute %s. Error code %d\n", shutdown_cmd_path, errno);
	else
		log_text("(MAIN) Executed %s.\n", shutdown_cmd_path);
}

