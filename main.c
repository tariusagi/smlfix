#include <windows.h>
#include <stdio.h>
#include <process.h>
#include "getopt.h"
#include "smlfix.h"

// -----------------------------------------------------------------------------  
// Global variables.
// -----------------------------------------------------------------------------  
char author_text[] =
	"Smartlaunch Fix Utitlity.\n"
	"Written by Phuong \"Uzi\" Vu, vuluuphuong@gmail.com.\n";

char usage_text[] = 
	"Syntax:\n"
	"    smlfix [-efLvw] [-a shutdown|reboot|logoff|ignore] [-c seconds]\n"
	"           [-l path] [-p path] [-t count]\n"
	"where:\n"
	"    -a           Action to take when Smartlaunch process was attacked, must be\n"
	"                 one of these:\n"
	"                     shutdown      Shutdown the computer\n"
	"                     reboot        Reboot the computer\n"
	"                     reboot2       Reboot the computer using system shutdown command\n"
	"                     logoff        Log off the current user\n"
	"                     ignore        Do nothing and terminate all watchdogs. This\n"
	"                                   is default.\n"
	"    -c n         Time (in seconds) before taking action after the Smartlaunch\n"
	"                 process was attacked (default is 10 seconds).\n"
	"    -e           Execute userinit.exe (DO NOT use this when already logged on).\n"
	"    -f           Fix Smartlaunch settings.\n"
	"    -h path      Watchdog's host (default is $WINDIR\\System32\\winlogon.exe).\n"
	"    -l path      Log file (default is $WINDIR\\smlfix.log).\n"
	"    -L           Enable log (NOT recommended in production).\n"
	"    -p path      Smartlaunch client folder (where Client.exe resides).\n"
	"    -v           Run verbosely.\n"
	"    -w           Install watchdog (RECOMMENDED).\n";

BOOL run_userinit_flag = FALSE;
BOOL fix_sml_flag = FALSE;
int countdown_flag = 10;
action_t watchdog_action_flag = ACTION_IGNORE;
BOOL install_watchdog_flag = FALSE;
BOOL unload_watchdog_flag = FALSE;
char sml_path[MAX_PATH] = "";
char host_path[MAX_PATH] = "";

shared_mem_t *shmem = NULL;

static SECURITY_ATTRIBUTES sec_attrib = {0};
static HANDLE sec_attrib_handle = 0;

// -----------------------------------------------------------------------------  
// Routines prototypes.
// -----------------------------------------------------------------------------  
void init_settings();
int parse_cmdline(int argc, char **argv);
void print_settings();
BOOL install_watchdog();
void exec_userinit();
void fix_sml_settings();
void print_if();
BOOL unload_watchdogs();
BOOL create_dummy_sa();
void free_dummy_sa();

// -----------------------------------------------------------------------------  
// Routines bodies.
// -----------------------------------------------------------------------------  
int main(int argc, char **argv)
{
	init_settings();

	if (!parse_cmdline(argc, argv))
	{
		printf(author_text);
#ifndef HIDE_USAGE
		printf(usage_text);
#endif
		return 1;
	}

	// Set DEBUG privilege for this process so it can do special stuffs.
	if (!set_debug_priv())
	{
		fprintf(stderr, "Couldn't set debug privilege. Terminating...\n");
		return 1;
	}

	if (unload_watchdog_flag)
	{
		if (unload_watchdogs())
			printf("Watchdog was successfully unloaded.\n");
		else
			fprintf(stderr, "Couldn't unload watchdog. It may not be running.\n");

		return 0;
	}

	if (verbose_flag)
		print_settings();

	if (fix_sml_flag)
		fix_sml_settings();

	if (run_userinit_flag)
		exec_userinit();

	if (install_watchdog_flag)
		install_watchdog();

	return 0;
}

void init_settings()
{
	GetEnvironmentVariable("ProgramFiles", sml_path, MAX_PATH);
	strcat(sml_path, "\\Smartlaunch\\Client");

	GetEnvironmentVariable("Windir", log_path, MAX_PATH);
	strcat(log_path, "\\smlfix.log");

	GetEnvironmentVariable("Windir", host_path, MAX_PATH);
	strcat(host_path, "\\system32\\winlogon.exe");
}

BOOL parse_cmdline(int argc, char **argv)
{
	char c;
	BOOL ret_val = TRUE;

	if (argc < 2)
		return FALSE;

	opterr = 0;

	while ((c = getopt(argc, argv, "a:c:efh:l:Lnp:uvw")) != -1)
	{
		switch (c)
		{
			case 'a':
				if (strcmp(optarg, "ignore") == 0)
					watchdog_action_flag = ACTION_IGNORE;
				else if (strcmp(optarg, "logoff") == 0)
					watchdog_action_flag = ACTION_LOGOFF;
				else if (strcmp(optarg, "reboot") == 0)
					watchdog_action_flag = ACTION_REBOOT;
				else if (strcmp(optarg, "reboot2") == 0)
					watchdog_action_flag = ACTION_REBOOT2;
				else if (strcmp(optarg, "shutdown") == 0)
					watchdog_action_flag = ACTION_SHUTDOWN;
				else
				{
					printf("ERROR: syntax error.\n");
					ret_val = FALSE;
				}
				break;

			case 'c':
				countdown_flag = atoi(optarg);
				break;

			case 'e':
				run_userinit_flag = TRUE;
				break;

			case 'f':
				fix_sml_flag = TRUE;
				break;

			case 'h':
				strcpy(host_path, optarg);
				break;

			case 'l':
				strcpy(log_path, optarg);
				break;

			case 'L':
				log_flag = TRUE;
				break;

			case 'p':
				strcpy(sml_path, optarg);
				break;

			case 'w':
				install_watchdog_flag = TRUE;
				break;

			case 'u':
				unload_watchdog_flag = TRUE;
				break;

			case 'v':
				verbose_flag = TRUE;
				break;

			case '?':
				printf("ERROR: syntax error.\n");
				ret_val = FALSE;
				break;

			default:
				ret_val = FALSE;
				break;
		}
	}

	return ret_val;
}

void print_settings()
{
	if (run_userinit_flag)
		printf("%-30s%s\n", "Execute userinit.exe", "yes");
	else
		printf("%-30s%s\n", "Execute userinit.exe", "no");

	if (fix_sml_flag)
		printf("%-30s%s\n", "Fix Smartlaunch settings", "yes");
	else
		printf("%-30s%s\n", "Fix Smartlaunch settings", "no");

	printf("%-30s%s\n", "Smartlaunch client folder", sml_path);

	if (install_watchdog_flag)
	{
		printf("%-30s%s\n", "Install watchdog", "yes");
		printf("%-30s%s\n", "Watchdog host", host_path);
		printf("%-30s%d\n", "Countdown seconds", countdown_flag);

		switch (watchdog_action_flag)
		{
			case ACTION_IGNORE:
				printf("%-30s%s\n", "Watchdog action", "ignore");
				break;
			case ACTION_LOGOFF:
				printf("%-30s%s\n", "Watchdog action", "logoff");
				break;
			case ACTION_REBOOT:
				printf("%-30s%s\n", "Watchdog action", "reboot");
				break;
			case ACTION_REBOOT2:
				printf("%-30s%s\n", "Watchdog action", "reboot2");
				break;
			case ACTION_SHUTDOWN:
				printf("%-30s%s\n", "Watchdog action", "shutdown");
				break;
		}
	}
	else
		printf("%-30s%s\n", "Install watchdog", "no");

	if (log_flag)
	{
		printf("%-30s%s\n", "Log to file", "yes");
		printf("%-30s%s\n", "Log file", log_path);
	}
	else
		printf("%-30s%s\n", "Log to file", "no");
}

BOOL install_watchdog()
{
	DWORD pid;
	HANDLE mutex_handle;
	HANDLE map_file_handle;
	shared_mem_t *shared_mem_ptr;
	DWORD err;

	log_text("Installing watchdog(s)...");

	// Find the host process.
	pid = get_pid_from_path(host_path, -1);
	
	if (!pid)
	{
		log_error(0, "There's no process executed from %s", host_path);
		return FALSE;
	}

	// Create a mutex to control access to shared data.
	log_text("Creating mutex...");

	create_dummy_sa();
	mutex_handle = CreateMutex(&sec_attrib, FALSE, MUTEX_NAME);
	err = GetLastError();
	free_dummy_sa();

	if (mutex_handle == NULL)
	{
		log_error(0, "Couldn't create mutex object.");
		return FALSE;
	}
	else if (err == ERROR_ALREADY_EXISTS)
	{
		log_error(0, "Watchdog is already running. Please uninstall it first.");
		CloseHandle(mutex_handle);
		return FALSE;
	}

	// Create a shared data structure to transfer parameters to the watchdog.
	log_text("Creating shared data...");

	create_dummy_sa();
	map_file_handle = CreateFileMapping(INVALID_HANDLE_VALUE,
			&sec_attrib,
			PAGE_READWRITE,
			0,
			sizeof(shared_mem_t),
			SHARED_MEM_NAME);
	err = GetLastError();
	free_dummy_sa();

	if (map_file_handle == NULL)
	{
		log_error(0, "Couldn't create map file.");
		CloseHandle(mutex_handle);
		return FALSE;
	}
	else if (err == ERROR_ALREADY_EXISTS)
	{
		log_error(0, "Map file already exists.");
		CloseHandle(map_file_handle);
		CloseHandle(mutex_handle);
		return FALSE;
	}

	shared_mem_ptr = (shared_mem_t *)MapViewOfFile(map_file_handle,
			FILE_MAP_ALL_ACCESS,
			0,
			0,
			0);

	if (shared_mem_ptr == NULL)
	{
		log_error(0, "Couldn't create a view of the map file.");
		CloseHandle(map_file_handle);
		CloseHandle(mutex_handle);
		return FALSE;
	}

	// Initialize shared memory data.
	shared_mem_ptr->verbose = verbose_flag;
	shared_mem_ptr->disable_logging = log_flag;
	strcpy(shared_mem_ptr->log_path, log_path);
	shared_mem_ptr->countdown = countdown_flag;
	shared_mem_ptr->watchdog_action = watchdog_action_flag;
	strcpy(shared_mem_ptr->sml_path, sml_path);
	shared_mem_ptr->unload = FALSE;
	
	// Now inject the watchdog code to the host process.
	if (inject_dll(pid, DLL_NAME) != TRUE)
	{
		log_error(0, "Couldn't inject watchdog code into host process.");

		UnmapViewOfFile(shared_mem_ptr);
		CloseHandle(map_file_handle);
		CloseHandle(mutex_handle);

		return FALSE;
	}

	log_text("Watchdog was installed.");

	UnmapViewOfFile(shared_mem_ptr);
	CloseHandle(map_file_handle);
	CloseHandle(mutex_handle);

	return TRUE;
}

BOOL unload_watchdogs()
{
	HANDLE mutex_handle;
	HANDLE map_file_handle;
	shared_mem_t *shared_mem_ptr;
	DWORD wait_result;
	BOOL ret_val = FALSE;

	// Open the mutex created by the injected thread.
	mutex_handle = OpenMutex(MUTEX_ALL_ACCESS, FALSE, MUTEX_NAME);

	if (mutex_handle == NULL)
	{
		log_error(0, "Couldn't open mutex. Error code %ld.", GetLastError());
		return ret_val;
	}

	wait_result = WaitForSingleObject(mutex_handle, 5000);

	switch (wait_result)
	{
		case WAIT_OBJECT_0:
			log_text("Updating watchdog data...");
			map_file_handle = OpenFileMapping(FILE_MAP_ALL_ACCESS,
					FALSE,
					SHARED_MEM_NAME);

			if (map_file_handle == NULL)
			{
				log_error(0, "Couldn't open map file. Error code %ld.", GetLastError());
			}
			else
			{
				shared_mem_ptr = (shared_mem_t *)MapViewOfFile(map_file_handle,
						FILE_MAP_ALL_ACCESS,
						0,
						0,
						0);

				if (shared_mem_ptr == NULL)
					log_error(0, "Couldn't open shared memory. Error code %ld.", GetLastError());
				else
				{
					log_text("Order watchdog to unload.");
					shared_mem_ptr->unload = TRUE;
					UnmapViewOfFile(shared_mem_ptr);
					ret_val = TRUE;
				}

				CloseHandle(map_file_handle);
			}

			ReleaseMutex(mutex_handle);
			break;

		case WAIT_TIMEOUT:
			log_error(0, "Couldn't get the mutex.");
			return FALSE;
	}

	CloseHandle(mutex_handle);

	return ret_val;
}

void exec_userinit()
{
	char userinit_path[MAX_PATH];

	GetEnvironmentVariable("Windir", userinit_path, MAX_PATH);
	strcat(userinit_path, "\\system32\\userinit.exe");
	if (spawnl(_P_NOWAIT, userinit_path, userinit_path, NULL) == (intptr_t) NULL)
		log_error(errno, "Couldn't execute %s.", userinit_path);
	else
		log_text("Executed %s.", userinit_path);
}

void fix_sml_settings()
{
	unsigned char ipv4_b1, ipv4_b2, ipv4_b3, ipv4_b4;
	FILE *f, *f2;
	char sml_inf[MAX_PATH];
	char sml_inf2[MAX_PATH];
	int sml_pc_id;
	char line[4000];
	// Will try to get this computer's IP no more than 10 times.
	int attempts = 10;
	
	log_text("Fixing Smartlaunch settings...");

	log_text("Getting current IP...");

	// Repeat attempts to get this computer's IP, until the IP is get, or max 
	// attempts has been reached. Each attempt wait 10 seconds.
	while (attempts && (!get_ipv4_bytes(&ipv4_b1, &ipv4_b2, &ipv4_b3, &ipv4_b4)))
	{
		attempts--;
		Sleep(10000);
	}

	// Successfully get the IP? Then compute the client ID.
	if (attempts)
	{
		sml_pc_id = ipv4_b3 * 254 + ipv4_b4;
		log_text("The client ID is %d.", sml_pc_id);
	}
	// Failed to get the IP? Log the incident.
	else
	{
		log_error(0, "Couldn't get the current IP. Networking may be down.");
		return;
	}

	// Prepare to fix the client's configuration file.
	// Build the path to the client's configuration file.
	strcpy(sml_inf, sml_path);
	strcat(sml_inf, "\\Data\\Inf\\Client.inf");
	// Build the path to the temporary file.
	strcpy(sml_inf2, sml_inf);
	strcat(sml_inf2, ".fixed");

	// Cannot open the client's configuration file? Log the incident.
	if ((f = fopen(sml_inf, "r")) == NULL)
	{
		log_error(0, "The Smartlaunch configuration file \"%s\" doesn't exist.", sml_inf);
	}
	// Successfully opened the client's configuration file.
	else
	{
		// Try to open the temporary file for writing.
		// Failed? Then we cannot fix the settings. So log the incident and quit this function.
		if ((f2 = fopen(sml_inf2, "w")) == NULL)
		{
			fclose(f);
			log_error(0, "Couldn't create temporary configuration file \"%s\".", sml_inf2);
			log_error(0, "The Smartlaunch configuration file was NOT fixed.");
			return;
		}
		// Temporary file opened? Now copy content of the client's config file
		// to the temporary file, line by line, and fix the settings on the fly.
		while (fgets(line, sizeof(line), f) != NULL) {
			// Fix the computer number.
			if (strstr(line, "ComputerNumber=") == line) {
				fprintf(f2, "ComputerNumber=%d\n", sml_pc_id);
			}
			// Fix the computer name.
			else if (strstr(line, "ComputerName=") == line) {
				fprintf(f2, "ComputerName=PC%03d\n", sml_pc_id);
			}
			// Copy as-is.
			else fwrite(line, strlen(line), 1, f2);
		}

		fclose(f);
		fclose(f2);
		remove(sml_inf);
		rename(sml_inf2, sml_inf);
		log_text("The Smartlaunch configuration file was fixed.");
	}
}

//---------------------------------------------------------------------------
// This creates a NULL-DACL-SD (a real SD, but with an all-access DACL).
// Passing NULL for a security descriptor under NT5 gets you an SD
// which has only CREATOR/OWNER and SYSTEM access. 
//
// The method below gets everyone access to the object, which is what I 
// want for cross-account objects like exclusion mutexes (which can be 
// created by current user or the LOCALSYSTEM account but must be visible 
// to both).
BOOL create_dummy_sa()
{
   BOOL ret_val = FALSE;

   sec_attrib.nLength = sizeof(sec_attrib);
   sec_attrib_handle = GlobalAlloc (GHND,SECURITY_DESCRIPTOR_MIN_LENGTH);
   sec_attrib.lpSecurityDescriptor = GlobalLock(sec_attrib_handle);
   sec_attrib.bInheritHandle = TRUE;

   if (InitializeSecurityDescriptor (sec_attrib.lpSecurityDescriptor, 1))
   {
      if (SetSecurityDescriptorDacl (sec_attrib.lpSecurityDescriptor,
                                     TRUE,
                                     NULL,
                                     FALSE))
      {
         ret_val = TRUE;
      }
      else
      {
         //OutputDebugString ("CNDS: cannot set security descriptor DACL\n");
         log_error(0, "Cannot set security descriptor DACL.");
      }
   }
   else
   {
      // OutputDebugString("CNDS: cannot initialise security descriptor\n");
      log_error(0, "Cannot initialise security descriptor.");
   }
   return ret_val;
}

//---------------------------------------------------------------------------
void free_dummy_sa()
{
   GlobalUnlock(sec_attrib_handle);
   GlobalFree(sec_attrib_handle);
}

