#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include "utils.h"
#include "process.h"

int find_process_by_name(PCTSTR swzName, DWORD *pdwPID)
{
   int res = 0;
   HANDLE hSnapshot = INVALID_HANDLE_VALUE;
   PROCESSENTRY32 procEntry = { 0 };
   DWORD dwPID = 0;
   DWORD dwPatternLen = _tcslen(swzName) + 3;
   PTSTR swzPattern = safe_alloc(dwPatternLen * sizeof(WCHAR));
   if (swzName[0] != TEXT('*'))
      _tcscat_s(swzPattern, dwPatternLen, TEXT("*"));
   _tcscat_s(swzPattern, dwPatternLen, swzName);
   if (swzName[_tcslen(swzName) - 1] != TEXT('*'))
      _tcscat_s(swzPattern, dwPatternLen, TEXT("*"));

   ZeroMemory(&procEntry, sizeof(procEntry));
   procEntry.dwSize = sizeof(procEntry);

   hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

   if (!Process32First(hSnapshot, &procEntry))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: Process32First() failed with code %u\n"), res);
      goto cleanup;
   }
   do
   {
      // The special keyword "caller" returns the PID of our parent process.
      // Parent-child process relations are not maintained by the OS, so this lookup may
      // fail if our parent has already exited.
      if (_tcsicmp(swzPattern, TEXT("*caller*")) == 0)
      {
         if (procEntry.th32ProcessID == GetCurrentProcessId())
         {
            dwPID = procEntry.th32ParentProcessID;
            break;
         }
         continue;
      }
      if (PathMatchSpec(procEntry.szExeFile, swzPattern))
      {
         if (dwPID != 0)
         {
            res = ERROR_TOO_MANY_MODULES;
            goto cleanup;
         }
         dwPID = procEntry.th32ProcessID;
      }
   }
   while (Process32Next(hSnapshot, &procEntry));

   if (dwPID == 0)
      res = ERROR_PATH_NOT_FOUND;
   else
      *pdwPID = dwPID;

cleanup:
   if (hSnapshot != INVALID_HANDLE_VALUE)
      CloseHandle(hSnapshot);
   if (swzPattern != NULL)
      safe_free(swzPattern);
   return res;
}

int open_process(DWORD dwPID, DWORD dwRightsRequired, PHANDLE phOut)
{
   int res = 0;
   HANDLE hProc = NULL;

   if (phOut == NULL || (*phOut != INVALID_HANDLE_VALUE && *phOut != NULL))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   hProc = OpenProcess(dwRightsRequired, FALSE, dwPID);
   if (hProc == NULL)
   {
      res = GetLastError();
      goto cleanup;
   }

   *phOut = hProc;

cleanup:
   return res;
}

int enumerate_processes_with(DWORD dwDesiredAccess)
{
   int res = 0;
   HANDLE hSnapshot = INVALID_HANDLE_VALUE;
   PROCESSENTRY32 procEntry = { 0 };
   DWORD dwPID = 0;

   ZeroMemory(&procEntry, sizeof(procEntry));
   procEntry.dwSize = sizeof(procEntry);

   hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

   if (!Process32First(hSnapshot, &procEntry))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: Process32First() failed with code %u\n"), res);
      goto cleanup;
   }
   do
   {
      HANDLE hProc = INVALID_HANDLE_VALUE;

      if (procEntry.th32ProcessID == 0)
         continue; // skip the idle pseudo-process

      res = open_process(procEntry.th32ProcessID, dwDesiredAccess, &hProc);
      if (res == 0)
      {
         _tprintf(TEXT(" [.] Process %u (%s)\n"), procEntry.th32ProcessID, procEntry.szExeFile);
         CloseHandle(hProc);
      }
      else if (res != ERROR_ACCESS_DENIED)
      {
         _ftprintf(stderr, TEXT(" [!] Warning: opening process %u (%s) failed with code %u\n"), dwPID, procEntry.szExeFile, res);
      }
   }
   while (Process32Next(hSnapshot, &procEntry));

cleanup:
   if (hSnapshot != INVALID_HANDLE_VALUE)
      CloseHandle(hSnapshot);
   return res;
}

