#include <windows.h>
#include <stdio.h>
#include <process.h>
#include "smlfix.h"

int smlId = 0;

int main(int argc, char **argv) 
{ 
	int attempts;
	char *ip;
	FILE *f, *f2;
	DWORD winlogonPid;

	WriteLog("========================================.");
	WriteLog("Started.");

	// Read the initial settings.
	if (!ReadIni())
		return -1;

	// Find the computer's number and name bases on the IP.
	if (!GetMachineIp(&ip))
		return 1;

	// If the machine IP is 127.0.0.1, then the network connection may not be
	// established. I will make several attempts to get the IP again.
	attempts = 10;

	while (attempts && (_stricmp(ip, "127.0.0.1") == 0))
	{
		attempts--;

		// Wait 10 seconds between attempts.
		Sleep(10000);

		if (!GetMachineIp(&ip))
			return 0;
	}

	if (attempts)
	{
		smlId = atoi((char *)(strrchr(ip, '.') + 1));
		WriteLog("The client ID is %d.", smlId);
	}
	else
	{
		WriteLog("Unable to obtain the IP address. Network connection might be failed.");
		WriteLog("Terminating...");
		return 0;
	}

	// Find and fix the Smartlaunch INF.
	if ((f = fopen(smlInfPath, "r")) == NULL)
		WriteLog("The Smartlaunch client INF doesn't exist.");
	else
	{
		char buf[4001];
		sprintf(buf, "%s.fix", smlInfPath);
		f2 = fopen(buf, "w");

		while (fgets(buf, 4000, f) != NULL)
		{
			if (strstr(buf, "ComputerNumber=") == buf)
			{
				// Fix the computer number.
				fprintf(f2, "ComputerNumber=%d\n", smlId);
			}
			else if (strstr(buf, "ComputerName=") == buf)
			{
				// Fix the computer name.
				fprintf(f2, "ComputerName=%s%03d\n", smlPrefix, smlId);
			}
			else
				fwrite(buf, strlen(buf), 1, f2);
		}

		fclose(f);
		fclose(f2);
		remove(smlInfPath);
		sprintf(buf, "%s.fix", smlInfPath);
		rename(buf, smlInfPath);
		WriteLog("The Smartlaunch client INF was fixed.");
	}

	// Spawn userinit.exe to continue the Windows logon process.
	WriteLog("Spawning userinit.exe...");
	_spawnl(_P_NOWAIT, "C:\\WINDOWS\\system32\\userinit.exe", NULL);
	WriteLog("userinit.exe was spawned.");

	// Inject DLL into the winlogon.exe.
	winlogonPid = GetPidFromName("winlogon.exe");

	while (!winlogonPid)
	{
		Sleep(1000);
		winlogonPid = GetPidFromName("winlogon.exe");
	}

	InjectDll(winlogonPid, "smlfix.dll");

	return 0;
}
