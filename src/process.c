#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "include\utils.h"
#include "include\process.h"

int create_process_with_token(HANDLE hToken, PTSTR swzCommandLine, PHANDLE phNewProcess)
{
   int res = 0;
   HANDLE hNewToken = INVALID_HANDLE_VALUE;
   STARTUPINFOEX startupInfo = { 0 };
   PROCESS_INFORMATION procInfo = { 0 };
   ZeroMemory(&startupInfo, sizeof(startupInfo));
   ZeroMemory(&procInfo, sizeof(procInfo));
   startupInfo.StartupInfo.cb = sizeof(startupInfo);

   if (hToken == NULL || hToken == INVALID_HANDLE_VALUE || swzCommandLine == NULL || phNewProcess == NULL || (*phNewProcess != NULL && *phNewProcess != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   if (!DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: DuplicateTokenEx() failed with code %u\n"), res);
      goto cleanup;
   }

   if (!CreateProcessAsUser(hToken, NULL, swzCommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, (LPSTARTUPINFO)&startupInfo, &procInfo))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: CreateProcessAsUser() failed with code %u\n"), res);
      goto cleanup;
   }

   CloseHandle(procInfo.hThread);
   *phNewProcess = procInfo.hProcess;

cleanup:
   if (hNewToken != INVALID_HANDLE_VALUE)
      CloseHandle(hNewToken);
   return res;
}

int create_reparented_process(HANDLE hParentProcess, PTSTR swzCommandLine, PHANDLE phNewProcess)
{
   int res = 0;
   STARTUPINFOEX startupInfo = { 0 };
   PROCESS_INFORMATION procInfo = { 0 };
   SIZE_T dwAttrListBytes = 0;
   ZeroMemory(&startupInfo, sizeof(startupInfo));
   ZeroMemory(&procInfo, sizeof(procInfo));
   startupInfo.StartupInfo.cb = sizeof(startupInfo);

   if (hParentProcess == NULL || hParentProcess == INVALID_HANDLE_VALUE || swzCommandLine == NULL || phNewProcess == NULL || (*phNewProcess != NULL && *phNewProcess != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, &dwAttrListBytes);
   startupInfo.lpAttributeList = safe_alloc(dwAttrListBytes);
   if (!InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, &dwAttrListBytes))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: InitializeProcThreadAttributeList() failed with code %u\n"), res);
      goto cleanup;
   }
   if (!UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(hParentProcess), NULL, NULL))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) failed with code %u\n"), res);
      goto cleanup;
   }

   if (!CreateProcess(NULL, swzCommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&startupInfo, &procInfo))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: CreateProcess() failed with code %u\n"), res);
      goto cleanup;
   }

   CloseHandle(procInfo.hThread);
   *phNewProcess = procInfo.hProcess;

cleanup:
   if (startupInfo.lpAttributeList != NULL)
   {
      DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
      safe_free(startupInfo.lpAttributeList);
   }
   return res;
}

int find_process_by_name(PCTSTR swzName, DWORD *pdwPID)
{
   int res = 0;
   HANDLE hSnapshot = INVALID_HANDLE_VALUE;
   PROCESSENTRY32 procEntry = { 0 };
   DWORD dwPID = 0;
   DWORD dwPatternLen = (DWORD)_tcslen(swzName) + 3;
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

int open_nt_process_object(PCTSTR swzTarget, target_t *pTargetType, DWORD dwRightsRequired, PHANDLE phOut)
{
   UNREFERENCED_PARAMETER(pTargetType);
   int res = 0;
   long lID = 0;
   DWORD dwPID = 0;

   errno = 0;
   lID = _tstol(swzTarget);

   if (lID > 0 && errno == 0)
   {
      dwPID = (DWORD)lID;
   }
   else if (_tcsicmp(swzTarget, TEXT("current")) == 0)
   {
      dwPID = GetCurrentProcessId();
   }
   else
   {
      res = find_process_by_name(swzTarget, &dwPID);
      if (res != 0)
         goto cleanup;
   }
   res = open_nt_process_by_pid(dwPID, dwRightsRequired, phOut);

cleanup:
   return res;
}

int open_nt_process_by_pid(DWORD dwPID, DWORD dwRightsRequired, PHANDLE phOut)
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

      res = open_nt_process_by_pid(procEntry.th32ProcessID, dwDesiredAccess, &hProc);
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

int list_modules(HANDLE hProcess, HANDLE hSnapshot, PMODULEENTRY32 *ppList, PSIZE_T pdwCount)
{
   int res = 0;
   MODULEENTRY32 modEntry = { 0 };
   PMODULEENTRY32 pList = NULL;
   SIZE_T dwCount = 0;

   if (ppList == NULL || *ppList != NULL || pdwCount == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   modEntry.dwSize = sizeof(modEntry);
   if (!Module32First(hSnapshot, &modEntry))
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: Module32First() failed on process %u with code %u\n"), GetProcessId(hProcess), res);
      goto cleanup;
   }

   do
   {
      pList = safe_realloc(pList, (dwCount + 1) * sizeof(modEntry));
      memcpy(&(pList[dwCount]), &modEntry, sizeof(modEntry));
      dwCount++;
   }
   while (Module32Next(hSnapshot, &modEntry));

   if (GetLastError() != ERROR_NO_MORE_FILES)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: Module32Next() failed on process %u with code %u\n"), GetProcessId(hProcess), res);
   }

   *ppList = pList;
   *pdwCount = dwCount;

cleanup:
   if (res != 0 && pList != NULL)
      safe_free(pList);
   return res;
}

PVOID round_down_to_allocated_block(PVOID pIn)
{
   static SYSTEM_INFO sysInfo = { 0 };

   if (sysInfo.dwPageSize == 0)
      GetSystemInfo(&sysInfo);

   return (PVOID)(((SIZE_T)pIn) & ~(((SIZE_T)sysInfo.dwAllocationGranularity) - 1));
}

int list_heaps(HANDLE hProcess, HANDLE hSnapshot, PVOID **ppList, PSIZE_T pdwCount)
{
   int res = 0;
   HEAPLIST32 heapList = { 0 };
   HEAPENTRY32 heapEntry = { 0 };
   PVOID *pList = NULL;
   SIZE_T dwCount = 0;

   if (ppList == NULL || *ppList != NULL || pdwCount == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   *pdwCount = 0;
   heapList.dwSize = sizeof(heapList);
   if (!Heap32ListFirst(hSnapshot, &heapList))
   {
      if (GetLastError() == ERROR_NO_MORE_FILES) // process with no heap
         goto cleanup;
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: Heap32ListFirst() failed on process %u with code %u\n"), GetProcessId(hProcess), res);
      goto cleanup;
   }

   do
   {
      //printf("Heap Found -- id = %llu\n", heapList.th32HeapID);
      heapEntry.dwSize = sizeof(heapEntry);
      if (!Heap32First(&heapEntry, heapList.th32ProcessID, heapList.th32HeapID))
      {
         if (GetLastError() == ERROR_NO_MORE_FILES) // empty heap
            continue;
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Warning: Heap32First() failed on process %u with code %u\n"), GetProcessId(hProcess), res);
         goto cleanup;
      }
      do
      {
         BOOL bKnownBlock = FALSE;
         PVOID pBlockBase = round_down_to_allocated_block((PVOID)heapEntry.dwAddress);
         /*printf("%p\n", (PVOID)heapEntry.dwAddress);
         if (heapEntry.dwAddress >= 0x1DC2A530000 && heapEntry.dwAddress < 0x1DC2A540000)
         {
            printf("------ FOUND: %p / %p\n", (PVOID)heapEntry.dwAddress, pBlockBase);
            return 42;
         }*/
         for (SSIZE_T i = dwCount - 1; i >= 0; i--)
         {
            if (pList[i] == pBlockBase)
            {
               bKnownBlock = TRUE;
               break;
            }
         }
         if (!bKnownBlock)
         {
            dwCount++;
            pList = safe_realloc(pList, dwCount * sizeof(PVOID));
            pList[dwCount - 1] = pBlockBase;
         }
         heapEntry.dwSize = sizeof(heapEntry);
      }
      while (Heap32Next(&heapEntry));

      if (GetLastError() != ERROR_NO_MORE_FILES)
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Warning: Heap32Next() failed on process %u with code %u\n"), GetProcessId(hProcess), res);
      }

      heapList.dwSize = sizeof(heapList);
   }
   while (Heap32ListNext(hSnapshot, &heapList));

   if (GetLastError() != ERROR_NO_MORE_FILES)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Warning: Heap32Next() failed on process %u with code %u\n"), GetProcessId(hProcess), res);
   }

   *ppList = pList;
   *pdwCount = dwCount;

   printf(" Heap blocks: ");
   for (SIZE_T i = 0; i < dwCount; i++)
   {
      printf(" %p", pList[i]);
   }
   printf("\n");

cleanup:
   if (res != 0 && pList != NULL)
      safe_free(pList);
   return res;
}

int list_memmap(HANDLE hProcess)
{
   int res = 0;
   SYSTEM_INFO sysInfo = { 0 };
   HANDLE hSnapshot = INVALID_HANDLE_VALUE;
   MEMORY_BASIC_INFORMATION memInfo = { 0 };
   PMODULEENTRY32 pListModules = NULL;
   SIZE_T dwCountModules = 0;
   PVOID *pListHeaps = NULL;
   SIZE_T dwCountHeaps = 0;
   PVOID pLastDisplayedBase = (PVOID)(-1);

   GetSystemInfo(&sysInfo);

   hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPHEAPLIST, GetProcessId(hProcess));
   if (hSnapshot == INVALID_HANDLE_VALUE)
   {
      _ftprintf(stderr, TEXT(" [!] Warning: CreateToolhelp32Snapshot() failed on process %u with code %u\n"), GetProcessId(hProcess), GetLastError());
   }
   else
   {
      list_modules(hProcess, hSnapshot, &pListModules, &dwCountModules);
      list_heaps(hProcess, hSnapshot, &pListHeaps, &dwCountHeaps);
   }

   for (PBYTE pQuery = NULL; ; pQuery = ((PBYTE)memInfo.BaseAddress) + memInfo.RegionSize)
   {
      if (VirtualQueryEx(hProcess, pQuery, &memInfo, sizeof(memInfo)) == 0)
      {
         if (GetLastError() == ERROR_INVALID_PARAMETER) // "error" used when pQuery is higher than the highest addressable byte
            break;
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Warning: querying memory layout at address %p failed with code %u\n"), pQuery, res);
         goto cleanup;
      }

      if (memInfo.State != MEM_COMMIT) // we're only interested in memory actually used
         continue;

      if (pLastDisplayedBase != memInfo.AllocationBase)
      {
         printf("%08p -- ", memInfo.AllocationBase);
         pLastDisplayedBase = memInfo.AllocationBase;
      }
      else
      {
         printf("                 `- ");
      }
      printf("%08p", memInfo.BaseAddress);
      printf(" | %8zx bytes | ", memInfo.RegionSize);

      switch (memInfo.Protect & (0x100 - 1))
      {
      case PAGE_NOACCESS:
         printf("---");
         break;
      case PAGE_READONLY:
         printf("R--");
         break;
      case PAGE_READWRITE:
      case PAGE_WRITECOPY:
         printf("RW-");
         break;
      case PAGE_EXECUTE:
         printf("--X");
         break;
      case PAGE_EXECUTE_READ:
         printf("R-X");
         break;
      case PAGE_EXECUTE_READWRITE:
      case PAGE_EXECUTE_WRITECOPY:
         printf("RWX");
         break;
      default:
         printf("%03X", memInfo.Protect);
      }
      printf("%s", memInfo.Protect & PAGE_GUARD ? "G" : "-");
      printf(" | Originally ");
      switch (memInfo.AllocationProtect & (0x100 - 1))
      {
      case PAGE_NOACCESS:
         printf("---");
         break;
      case PAGE_READONLY:
         printf("R--");
         break;
      case PAGE_READWRITE:
      case PAGE_WRITECOPY:
         printf("RW-");
         break;
      case PAGE_EXECUTE:
         printf("--X");
         break;
      case PAGE_EXECUTE_READ:
         printf("R-X");
         break;
      case PAGE_EXECUTE_READWRITE:
      case PAGE_EXECUTE_WRITECOPY:
         printf("RWX");
         break;
      default:
         printf("%03X", memInfo.AllocationProtect);
      }
      printf("%s | ", memInfo.AllocationProtect & PAGE_GUARD ? "G" : "-");

      BOOL bFound = FALSE;
      for (SIZE_T i = 0; i < dwCountModules; i++)
      {
         if (memInfo.AllocationBase == pListModules[i].modBaseAddr)
         {
            printf("Module %ws", pListModules[i].szExePath);
            bFound = TRUE;
            break;
         }
      }

      WCHAR swzMappedPath[MAX_PATH] = { 0 };
      if (!bFound && GetMappedFileNameW(hProcess, memInfo.BaseAddress, swzMappedPath, MAX_PATH) != 0)
      {
         printf("Mapped file %ws", swzMappedPath);
      }
      else if (!bFound)
      {
         for (SIZE_T i = 0; i < dwCountHeaps; i++)
         {
            if (memInfo.AllocationBase == pListHeaps[i])
            {
               printf("[heap]");
               break;
            }
         }
      }
      printf("\n");
   }

cleanup:
   if (hSnapshot != INVALID_HANDLE_VALUE)
      CloseHandle(hSnapshot);
   return res;
}