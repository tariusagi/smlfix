#include <windows.h>
#include <process.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include "smlfix.h"

typedef DWORD (WINAPI *GETLASTERROR) (VOID);
typedef HMODULE (WINAPI *LOADLIBRARY) (LPCTSTR);
typedef HANDLE (WINAPI *OPENTHREAD) (DWORD, BOOL, DWORD);
typedef HANDLE (WINAPI *OPENPROCESS) (DWORD, BOOL, DWORD);
typedef DWORD (WINAPI *RESUMETHREAD) (HANDLE);
typedef HANDLE (WINAPI *OPENMUTEX) (DWORD, BOOL, LPCTSTR);
typedef DWORD (WINAPI *WAITSINGLEOBJECT) (HANDLE, DWORD);
typedef BOOL (WINAPI *CLOSEHANDLE) (HANDLE);
typedef VOID (WINAPI *SLEEP) (DWORD);
typedef DWORD (WINAPI *GETCURRENTPROCESSID) (VOID);
typedef HANDLE (WINAPI *GETCURRENTPROCESS) (VOID);
typedef BOOL (WINAPI *TERMINATEPROCESS) (HANDLE, UINT);
typedef BOOL (WINAPI *OPENPROCESSTOKEN) (HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *LOOKUPPRIVILEGEVALUE) (LPCTSTR, LPCTSTR, PLUID);
typedef BOOL (WINAPI *ADJUSTTOKENPRIVILEGES) (HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef BOOL (WINAPI *EXITWINDOWSEX) (UINT, DWORD);

typedef struct 
{
	// The primary watchdog thread's ID.
	DWORD				tid;
	DWORD				host_pid;
	// Action to take when the primary watchdog was terminated.
	int					action;
	// Pointers to WINAPI functions.
	GETLASTERROR		get_last_error;
	LOADLIBRARY			load_library;
	OPENTHREAD			open_thread;
	OPENPROCESS			open_process;
	RESUMETHREAD		resume_thread;
	OPENMUTEX			open_mutex;
	WAITSINGLEOBJECT	wait_singe_object;
	CLOSEHANDLE			close_handle;
	SLEEP				sleep;
	GETCURRENTPROCESSID	get_current_process_id;
	GETCURRENTPROCESS	get_current_process;
	TERMINATEPROCESS	terminate_process;
	OPENPROCESSTOKEN	open_process_token;
	LOOKUPPRIVILEGEVALUE	lookup_privilege_value;
	ADJUSTTOKENPRIVILEGES	adjust_token_privileges;
	EXITWINDOWSEX		exit_windows_ex;
} inject_data_t, *inject_data_ptr_t;

shared_mem_t *shared_mem_ptr;
HANDLE mutex_handle;
HANDLE map_file_handle;
HANDLE watchdog2_handle = 0;

BOOL install_watchdog2(DWORD pid);

void init_watchdog()
{
	mutex_handle = OpenMutex(MUTEX_ALL_ACCESS, FALSE, MUTEX_NAME);
	map_file_handle = OpenFileMapping(FILE_MAP_ALL_ACCESS,
			FALSE,
			SHARED_MEM_NAME);
	shared_mem_ptr = (shared_mem_t *)MapViewOfFile(map_file_handle,
			FILE_MAP_ALL_ACCESS,
			0,
			0,
			0);

	log_flag = shared_mem_ptr->disable_logging;
	strcpy(log_path, shared_mem_ptr->log_path);
}

void terminate_watchdog()
{
	UnmapViewOfFile(shared_mem_ptr);
	CloseHandle(map_file_handle);
	CloseHandle(mutex_handle);

	if (watchdog2_handle != NULL)
	{
		do_log("(WATCHDOG) Terminated secondary watchdog.");
		TerminateThread(watchdog2_handle, 0);
		CloseHandle(watchdog2_handle);
	}

	do_log("(WATCHDOG) Terminated.");

	FreeLibraryAndExitThread(GetModuleHandle(DLL_NAME), 0);
}

DWORD WINAPI watchdog_func(LPVOID data)
{
	DWORD session_id;
	DWORD sml_pid = 0;
	HANDLE sml_handle = NULL;
	BOOL sml_launched = FALSE;
	BOOL sml_missing = FALSE;
	int sml_countdown = 0;
	BOOL unload = FALSE;
	DWORD wait_result;
	char sml_exe[_MAX_PATH];

	strcpy(sml_exe, shared_mem_ptr->sml_path);
	strcat(sml_exe, "\\Client.exe");

	// Install 2nd watchdogs.
	ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
	install_watchdog2(get_pid_from_path(SECONDARY_HOST, session_id));

	do_log("(WATCHDOG) Watchdog is running (TID %ld)...", GetCurrentThreadId());

	// Main loop.
	while (!unload)
	{
		Sleep(1000);

		// Monitor Smartlauch client process.
		if (sml_launched)
		{
			if (sml_missing)
			{
				if ((sml_pid = get_pid_from_path(sml_exe, -1)) == 0)
				{
					sml_countdown--;
					do_log("(WATCHDOG) Counting down at %d...", sml_countdown);

					if (sml_countdown == 0)
					{
						do_log("(WATCHDOG) Countdown reached zero.");

						switch (shared_mem_ptr->watchdog_action)
						{
							case ACTION_LOGOFF:
								do_log("(WATCHDOG) Force logging off now.");
								force_reboot(ACTION_LOGOFF);
								unload = TRUE;
								break;

							case ACTION_REBOOT:
								do_log("(WATCHDOG) Force reboot now.");
								force_reboot(ACTION_REBOOT);
								unload = TRUE;
								break;

							case ACTION_REBOOT2:
								do_log("(WATCHDOG) Force a reboot now using system shutdown command.");
								force_reboot(ACTION_REBOOT2);
								unload = TRUE;
								break;

							case ACTION_SHUTDOWN:
								do_log("(WATCHDOG) Force shutdown now.");
								force_reboot(ACTION_SHUTDOWN);
								unload = TRUE;
								break;

							default:
								// Ignore and unload;
								unload = TRUE;
						}
					}
				}
				else
				{
					do_log("(WATCHDOG) Smartlaunch came back, PID %u", sml_pid);
					sml_missing = FALSE;
					sml_handle = OpenProcess(SYNCHRONIZE, FALSE, sml_pid);

					if (sml_handle == NULL)
					{
						do_error_log(GetLastError(), "(WATCHDOG) Couldn't open Smartlaunch process");
						// Unload for being useless now.
						break;
					}
				}
			}
			else
			{
				wait_result = WaitForSingleObject(sml_handle, 0);

				if (wait_result != WAIT_TIMEOUT)
				{
					// Smartlaunch process went missing. 
					CloseHandle(sml_handle);
					sml_missing = TRUE;
					// Set the countdown.
					sml_countdown = shared_mem_ptr->countdown;
					do_log("(WATCHDOG) Smartlaunch went missing. Started counting down at %d.", sml_countdown);
				}
				else
				{
					// Smartlaunch is alive. Make sure it run well.
					resume_process(sml_pid);
				}
			}
		}
		else
		{
			if ((sml_pid = get_pid_from_path(sml_exe, -1)) != 0)
			{
				do_log("(WATCHDOG) Smartlaunch was launched, PID %u", sml_pid);
				sml_launched = TRUE;
				sml_missing = FALSE;
				sml_handle = OpenProcess(SYNCHRONIZE, FALSE, sml_pid);

				if (sml_handle == NULL)
				{
					do_error_log(GetLastError(), "(WATCHDOG) Couldn't open Smartlaunch process");
					// Unload for being useless now.
					unload = TRUE;
				}
			}
		}

		if (!unload)
		{
			// Check the secondary watchdog.
			if (watchdog2_handle != NULL)
			{
				wait_result = WaitForSingleObject(watchdog2_handle, 0);

				if (wait_result == WAIT_TIMEOUT) 
				{
					// The secondary watchdog is alive.
					ResumeThread(watchdog2_handle);
				}
				else
				{
					DWORD session_id;
					ProcessIdToSessionId(GetCurrentProcessId(), &session_id);

					// The secondary watchdog was killed. Re-install it.
					install_watchdog2(get_pid_from_path(SECONDARY_HOST, session_id));
					do_log("(WATCHDOG) Second watchdog was re-installed.");
				}
			}

			// Checking for unload flag.
			do_log("(WATCHDOG) Checking for unload flag...");
			wait_result = WaitForSingleObject(mutex_handle, 1000);

			switch (wait_result)
			{
				case WAIT_OBJECT_0:
					unload = shared_mem_ptr->unload;
					ReleaseMutex(mutex_handle);
					break;

				case WAIT_TIMEOUT:
					do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the mutex");
					unload = TRUE;
					break;
			}
		}
	}

	terminate_watchdog();

	return 0;
}

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved)
{
	BOOL ret_val = TRUE;

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DWORD dwRes;
		PSID pEveryoneSID = NULL;
		PACL pACL = NULL;
		PSECURITY_DESCRIPTOR pSD = NULL;
		EXPLICIT_ACCESS ea[2];
		SID_IDENTIFIER_AUTHORITY SIDAuthWorld = {SECURITY_WORLD_SID_AUTHORITY};
		SECURITY_ATTRIBUTES sa;

		// Initialize watchdog local data.
		DisableThreadLibraryCalls(hDll);
		init_watchdog();


		// Create a well-known SID for the Everyone group.
		if(! AllocateAndInitializeSid( &SIDAuthWorld, 1,
						 SECURITY_WORLD_RID,
						 0, 0, 0, 0, 0, 0, 0,
						 &pEveryoneSID))
		{
			do_error_log(GetLastError(), "(DLL) AllocateAndInitializeSid failed");
			return FALSE;
		}

		// Initialize an EXPLICIT_ACCESS structure for an ACE.
		// The ACE will allow Everyone read access to the key.

		ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
		ea[0].grfAccessPermissions = THREAD_TERMINATE | THREAD_SUSPEND_RESUME;
		// ea[0].grfAccessPermissions = THREAD_SUSPEND_RESUME | THREAD_TERMINATE;
		ea[0].grfAccessMode = DENY_ACCESS;
		ea[0].grfInheritance= NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[0].Trustee.ptstrName  = (LPTSTR) pEveryoneSID;

		// Create a new ACL that contains the new ACEs.
		dwRes = SetEntriesInAcl(1, ea, NULL, &pACL);
		if (ERROR_SUCCESS != dwRes) {
			do_error_log(GetLastError(), "(DLL) SetEntriesInAcl failed");
			goto Cleanup;
		}

		// Initialize a security descriptor.  
		pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, 
								 SECURITY_DESCRIPTOR_MIN_LENGTH); 
		if (pSD == NULL) { 
			do_error_log(GetLastError(), "(DLL) LocalAlloc failed");
			ret_val = FALSE;
			goto Cleanup; 
		} 
		 
		if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {  
			do_error_log(GetLastError(), "(DLL) InitializeSecurityDescriptor failed");
			goto Cleanup; 
		} 
		 
		// Add the ACL to the security descriptor. 
		if (!SetSecurityDescriptorDacl(pSD, 
				TRUE,     // fDaclPresent flag   
				pACL, 
				FALSE))   // not a default DACL 
		{  
			do_error_log(GetLastError(), "(DLL) SetSecurityDescriptorDacl failed");
			ret_val = FALSE;
			goto Cleanup; 
		} 

		// Initialize a security attributes structure.
		sa.nLength = sizeof (SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = pSD;
		sa.bInheritHandle = FALSE;

		// Use the security attributes to set the security descriptor to the 
		// watchdog thread.
		if (CreateThread(&sa, 0, watchdog_func, 0, 0, NULL) == NULL)
		{
			do_error_log(GetLastError(), "(DLL) Couldn't create the primary watchdog thread");
			ret_val = FALSE;
		}

		Cleanup:

		if (pEveryoneSID) FreeSid(pEveryoneSID);
		if (pACL) LocalFree(pACL);
		if (pSD) LocalFree(pSD);
	}

	return ret_val;
}

static DWORD WINAPI watchdog2_func(inject_data_ptr_t inject_data)
{
	DWORD wait_result;
	HANDLE host_handle;
	HANDLE thread_handle;

	host_handle = inject_data->open_process(SYNCHRONIZE, FALSE, inject_data->host_pid);

	if (host_handle == NULL)
		return 0;
	
	thread_handle = inject_data->open_thread(THREAD_ALL_ACCESS,
			FALSE, inject_data->tid);

	if (thread_handle == NULL)
		return 0;

	while (1)
	{
		wait_result = inject_data->wait_singe_object(thread_handle, 0);

		if (wait_result == WAIT_TIMEOUT)
		{
			// Primary watchdog is still alive.
			inject_data->resume_thread(thread_handle);
		}
		else
		{
			// Primary watchdog was terminated.
			// Delay a bit.
			inject_data->sleep(1000);
			// Check if its host still exist.
			wait_result = inject_data->wait_singe_object(host_handle, 0);

			if (wait_result == WAIT_TIMEOUT)
			{
				// The host process is still alive.
				// So this was an attacke. Take an action!!!
				if (inject_data->action == ACTION_REBOOT)
				{
					// Kill myself process to force Windows to reboot.
					inject_data->terminate_process(inject_data->get_current_process(), 0);
				}

				// Anyhow, close the now invalid handles...
				inject_data->close_handle(thread_handle);
				inject_data->close_handle(host_handle);
				// ...and terminate.
				break;
			}
		}

		// Delay a bit before continue working.
		inject_data->sleep(1000);
	}

	return 1;
}

// -----------------------------------------------------------------------------
// This empty function marks the memory address after watchdog2_func.
// -----------------------------------------------------------------------------
static void thread_func_tail(void){}

// -----------------------------------------------------------------------------
// Inject code from watchdog2_func routine to the target process.
// -----------------------------------------------------------------------------
BOOL install_watchdog2(DWORD pid)
{	
	HMODULE		kernel32_handle;
	HMODULE		user32_handle;
	HMODULE		advapi32_handle;
	HANDLE		process_handle; 
	BYTE		*remote_data_ptr;
	DWORD		*remote_code_ptr;
	DWORD		watchdog2_tid = 0;
	DWORD 		written_bytes = 0;
	int			code_size;
	inject_data_t	local_data;

	do_log("(WATCHDOG) Installing secondary watchdog to PID %ld...", pid);

	process_handle = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION 
		| PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE, pid);

	if (process_handle == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't open host process");
		return FALSE;
	}

	// Initialize data structure which will be passed to watchdog2_func.
	local_data.tid = GetCurrentThreadId();
	local_data.host_pid = GetCurrentProcessId();
	local_data.action = shared_mem_ptr->watchdog_action;

	// Get addresses of kernel32 functions.
	kernel32_handle = GetModuleHandle("kernel32.dll");

	if (kernel32_handle == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get handle to kernel32 module");
		return FALSE;
	}

	local_data.get_last_error = (GETLASTERROR) GetProcAddress(kernel32_handle, "GetLastError");
	if (local_data.get_last_error == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of GetLastError");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.load_library = (LOADLIBRARY) GetProcAddress(kernel32_handle, "LoadLibraryA");
	if (local_data.load_library == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of LoadLibrary");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.open_thread = (OPENTHREAD) GetProcAddress(kernel32_handle, "OpenThread");
	if (local_data.open_thread == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of OpenThread");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.open_process = (OPENTHREAD) GetProcAddress(kernel32_handle, "OpenProcess");
	if (local_data.open_process == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of OpenProcess");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.resume_thread = (RESUMETHREAD) GetProcAddress(kernel32_handle, "ResumeThread");
	if (local_data.resume_thread == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of ResumeThread");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.open_mutex = (OPENMUTEX) GetProcAddress(kernel32_handle, "OpenMutexA");
	if (local_data.open_mutex == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of OpenMutex");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.wait_singe_object = (WAITSINGLEOBJECT) GetProcAddress(kernel32_handle, "WaitForSingleObject");
	if (local_data.wait_singe_object == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of WaitForSingleObject");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.close_handle = (CLOSEHANDLE) GetProcAddress(kernel32_handle, "CloseHandle");
	if (local_data.close_handle == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of CloseHandle");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.sleep = (SLEEP) GetProcAddress(kernel32_handle, "Sleep");
	if (local_data.sleep == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of Sleep");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.get_current_process_id = (GETCURRENTPROCESSID) GetProcAddress(kernel32_handle, "GetCurrentProcessId");
	if (local_data.get_current_process_id == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of GetCurrentProcessId");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.get_current_process = (GETCURRENTPROCESS) GetProcAddress(kernel32_handle, "GetCurrentProcess");
	if (local_data.get_current_process == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of GetCurrentProcess");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	local_data.terminate_process = (TERMINATEPROCESS) GetProcAddress(kernel32_handle, "TerminateProcess");
	if (local_data.terminate_process == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of TerminateProcess");
		CloseHandle(process_handle);
		CloseHandle(kernel32_handle);
		return FALSE;
	}

	CloseHandle(kernel32_handle);

	// Get addresses of user32 functions.
	user32_handle = GetModuleHandle("user32.dll");

	if (user32_handle == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get handle to user32 module");
		return FALSE;
	}

	local_data.exit_windows_ex = (EXITWINDOWSEX) GetProcAddress(kernel32_handle, "ExitWindowsExA");
	if (local_data.get_current_process == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of ExitWindowsEx");
		CloseHandle(process_handle);
		CloseHandle(user32_handle);
		return FALSE;
	}

	CloseHandle(user32_handle);

	// Get addresses of advapi32 functions.
	advapi32_handle = local_data.load_library("advapi32.dll");

	if (advapi32_handle == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get handle to advapi32 module");
		return FALSE;
	}

	local_data.open_process_token = (OPENPROCESSTOKEN) GetProcAddress(advapi32_handle, "OpenProcessToken");
	if (local_data.open_process_token == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of OpenProcessToken");
		CloseHandle(process_handle);
		CloseHandle(advapi32_handle);
		return FALSE;
	}

	local_data.lookup_privilege_value = (LOOKUPPRIVILEGEVALUE) GetProcAddress(advapi32_handle, "LookupPrivilegeValueA");
	if (local_data.lookup_privilege_value == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of LookupPrivilegeValue");
		CloseHandle(process_handle);
		CloseHandle(advapi32_handle);
		return FALSE;
	}

	local_data.adjust_token_privileges = (ADJUSTTOKENPRIVILEGES) GetProcAddress(advapi32_handle, "AdjustTokenPrivileges");
	if (local_data.adjust_token_privileges == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't get the address of AdjustTokenPrivileges");
		CloseHandle(process_handle);
		CloseHandle(advapi32_handle);
		return FALSE;
	}

	CloseHandle(advapi32_handle);

	// Inject watchdog2_func input data.
	remote_data_ptr = (PBYTE) VirtualAllocEx(process_handle,
			0,
			sizeof(local_data),
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE);

	if (remote_data_ptr == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't allocate memory for injecting data");
		CloseHandle(process_handle);
		return FALSE;
	}

	WriteProcessMemory(process_handle,
			remote_data_ptr,
			&local_data, 
			sizeof(local_data), 
			&written_bytes);

	// Inject watchdog2_func code.
	// Calculate the number of bytes that watchdog2_func occupies
	code_size = ((LPBYTE)thread_func_tail - (LPBYTE)watchdog2_func);

	remote_code_ptr = (PDWORD) VirtualAllocEx(
			process_handle
			, 0
			, code_size
			, MEM_COMMIT
			, PAGE_EXECUTE_READWRITE);		

	if (remote_code_ptr == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't allocate memory for injecting code");
		CloseHandle(process_handle);
		return FALSE;
	}

	WriteProcessMemory(
			process_handle
			, remote_code_ptr
			, &watchdog2_func
			, code_size
			, &written_bytes);

	if (!set_debug_priv())
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't set debug privilege");
		CloseHandle(process_handle);
		return FALSE;
	}

	// Start execution of remote watchdog2_func
	watchdog2_handle = CreateRemoteThread(
			process_handle, NULL, 0, 
			(LPTHREAD_START_ROUTINE) remote_code_ptr,
			remote_data_ptr,
			0 , &watchdog2_tid);

	if (watchdog2_handle == NULL)
	{
		do_error_log(GetLastError(), "(WATCHDOG) ERROR: couldn't create remote thread for injected code");
		CloseHandle(process_handle);
		return FALSE;
	}

	// I don't wait until the remote thread terminate.
	CloseHandle(process_handle);

	do_log("(WATCHDOG) Secondary watchdog was installed (TID %ld).", watchdog2_tid);

	return TRUE;
}

