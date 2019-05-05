#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <fltUser.h> // for FilterCommunicationPort objects
#include "process.h"
#include "registry.h"
#include "token.h"
#include "utils.h"
#include "nt.h"

typedef struct {
   PCTSTR swzNTPath;
   BOOL bFound;
   PTSTR swzType;
} nt_object_lookup_t;

static const nt_object_open_t pNTObjectTypes[][2] = {
   { (nt_object_open_t) TEXT("Directory"),            &open_nt_directory_object },
   { (nt_object_open_t) TEXT("SymbolicLink"),         &open_nt_symbolic_link_object },
   { (nt_object_open_t) TEXT("Mutant"),               &open_nt_mutant_object },
   { (nt_object_open_t) TEXT("Event"),                &open_nt_event_object },
   { (nt_object_open_t) TEXT("KeyedEvent"),           &open_nt_keyedevent_object },
   { (nt_object_open_t) TEXT("Section"),              &open_nt_section_object },
   { (nt_object_open_t) TEXT("Semaphore"),            &open_nt_semaphore_object },
   { (nt_object_open_t) TEXT("Timer"),                &open_nt_timer_object },
   { (nt_object_open_t) TEXT("Device"),               &open_nt_file_object },
   { (nt_object_open_t) TEXT("Session"),              &open_nt_session_object },
   { (nt_object_open_t) TEXT("Job"),                  &open_nt_job_object },
   { (nt_object_open_t) TEXT("Key"),                  &open_nt_key_object },
   { (nt_object_open_t) TEXT("FilterConnectionPort"), &open_nt_filterconnectionport_object },
   { (nt_object_open_t) TEXT("ALPC Port"),            &open_nt_alpcconnectionport_object },
   // No way to open these from userland:
   { (nt_object_open_t) TEXT("Callback"),             &open_nt_unsupported_object },
   { (nt_object_open_t) NULL,                         NULL }
};

#define OBJ_CASE_INSENSITIVE    0x00000040L
#define STATUS_NO_MORE_ENTRIES  0x8000001AL

#define InitializeObjectAttributes( p, n, a, r, s ) { \
   (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
   (p)->RootDirectory = r;                             \
   (p)->Attributes = a;                                \
   (p)->ObjectName = n;                                \
   (p)->SecurityDescriptor = s;                        \
   (p)->SecurityQualityOfService = NULL;               \
   }

PNtOpenDirectoryObject NtOpenDirectoryObject = NULL;
PNtQueryDirectoryObject NtQueryDirectoryObject = NULL;
PNtOpenFile NtOpenFile = NULL;
PNtQueryDirectoryFile NtQueryDirectoryFile = NULL;
PNtOpenSymbolicLinkObject NtOpenSymbolicLinkObject = NULL;
PNtOpenMutant NtOpenMutant = NULL;
PNtOpenEvent NtOpenEvent = NULL;
PNtOpenKeyedEvent NtOpenKeyedEvent = NULL;
PNtOpenSection NtOpenSection = NULL;
PNtOpenSemaphore NtOpenSemaphore = NULL;
PNtOpenTimer NtOpenTimer = NULL;
PNtOpenSession NtOpenSession = NULL;
PNtOpenJobObject NtOpenJobObject = NULL;
PNtOpenKeyEx NtOpenKeyEx = NULL;
PNtAlpcConnectPort NtAlpcConnectPort = NULL;
PNtQuerySystemInformation NtQuerySystemInformation = NULL;

static int do_import_function(HMODULE hLib, PCSTR swzFunctionName, PVOID pFunctionPtr)
{
   int res = 0;
   PVOID pRes = (PVOID)GetProcAddress(hLib, swzFunctionName);

   if (hLib == NULL || hLib == INVALID_HANDLE_VALUE || swzFunctionName == NULL || pFunctionPtr == NULL || *(PVOID*)pFunctionPtr != NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   if (pRes == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic import '%hs', failed with code %u\n"), swzFunctionName, res);
      goto cleanup;
   }
   *(PVOID*)pFunctionPtr = pRes;

cleanup:
   return res;
}

int resolve_imports()
{
   int res = 0;

   HMODULE hNTDLL = LoadLibrary(TEXT("ntdll.dll"));
   if (hNTDLL == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic imports, NTDLL load failed with code %u\n"), res);
      goto cleanup;
   }
   res = do_import_function(hNTDLL, "NtOpenDirectoryObject", &NtOpenDirectoryObject);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtQueryDirectoryObject", &NtQueryDirectoryObject);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenFile", &NtOpenFile);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtQueryDirectoryFile", &NtQueryDirectoryFile);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenSymbolicLinkObject", &NtOpenSymbolicLinkObject);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenMutant", &NtOpenMutant);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenEvent", &NtOpenEvent);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenKeyedEvent", &NtOpenKeyedEvent);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenSection", &NtOpenSection);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenSemaphore", &NtOpenSemaphore);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenTimer", &NtOpenTimer);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenSession", &NtOpenSession);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenJobObject", &NtOpenJobObject);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtOpenKeyEx", &NtOpenKeyEx);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtAlpcConnectPort", &NtAlpcConnectPort);
   if (res != 0)
      goto cleanup;
   res = do_import_function(hNTDLL, "NtQuerySystemInformation", &NtQuerySystemInformation);
   if (res != 0)
      goto cleanup;

cleanup:
   return res;
}

int open_target(PCTSTR swzTarget, target_t targetType, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   HANDLE hRes = INVALID_HANDLE_VALUE;

   if (targetType == TARGET_PROCESS)
   {
      DWORD dwTargetPID = 0;
      long lPID = 0;
      errno = 0;
      lPID = _tstol(swzTarget);
      if (lPID > 0 && errno == 0)
      {
         dwTargetPID = (DWORD)lPID;
      }
      else
      {
         res = find_process_by_name(swzTarget, &dwTargetPID);
         if (res == ERROR_TOO_MANY_MODULES)
         {
            _ftprintf(stderr, TEXT(" [!] Error: two or more processes found matching '%s'\n"), swzTarget);
            goto cleanup;
         }
         else if (res == ERROR_PATH_NOT_FOUND)
         {
            _ftprintf(stderr, TEXT(" [!] Error: no process found matching '%s'\n"), swzTarget);
            goto cleanup;
         }
      }
      _tprintf(TEXT(" [.] Operating on process %u\n"), dwTargetPID);
      hRes = OpenProcess(dwRightsRequired, FALSE, dwTargetPID);
      if (hRes == NULL)
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: opening process %u failed with code %u\n"), dwTargetPID, res);
         goto cleanup;
      }
      *phOut = hRes;
   }
   else if (targetType == TARGET_THREAD)
   {
      DWORD dwTargetTID = 0;
      long lTID = 0;
      errno = 0;
      lTID = _tstol(swzTarget);
      if (lTID <= 0 || errno != 0)
      {
         if (_tcsicmp(swzTarget, TEXT("current")) == 0)
         {
            lTID = GetCurrentThreadId();
         }
         else
         {
            res = -1;
            _ftprintf(stderr, TEXT(" [!] Error: option --thread requires a positive TID\n"));
            goto cleanup;
         }
      }
      dwTargetTID = (DWORD)lTID;
      _tprintf(TEXT(" [.] Operating on thread %u\n"), (DWORD)lTID);
      hRes = OpenThread(dwRightsRequired, FALSE, dwTargetTID);
      if (hRes == NULL)
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: opening thread %u failed with code %u\n"), dwTargetTID, res);
         goto cleanup;
      }
      *phOut = hRes;
   }
   else if (targetType == TARGET_REGKEY)
   {
      res = open_regkey_by_name(swzTarget, dwRightsRequired, (PHKEY)phOut);
      if (res == 0)
         _tprintf(TEXT(" [.] Operating on registry key %s\n"), swzTarget);
   }
   else if (targetType == TARGET_FILE)
   {
      hRes = CreateFile(swzTarget, dwRightsRequired, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
         FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
      if (hRes == INVALID_HANDLE_VALUE)
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: unable to open file or directory '%s', error code %u\n"), swzTarget, res);
         goto cleanup;
      }
      _tprintf(TEXT(" [.] Operating on file object %s\n"), swzTarget);
      *phOut = hRes;
   }
   else if (targetType == TARGET_PRIMARY_TOKEN)
   {
      HANDLE hProcess = INVALID_HANDLE_VALUE;
      res = open_target(swzTarget, TARGET_PROCESS, PROCESS_QUERY_INFORMATION, &hProcess);
      if (res != 0)
         goto cleanup;
      if (!OpenProcessToken(hProcess, dwRightsRequired, phOut))
      {
         res = GetLastError();
         _ftprintf(stderr, TEXT(" [!] Error: opening process token failed with code %u\n"), res);
         goto cleanup;
      }
      _tprintf(TEXT(" [.] Operating on primary token\n"));
   }
   else if (targetType == TARGET_IMPERSONATION_TOKEN)
   {
      HANDLE hThread = INVALID_HANDLE_VALUE;
      res = open_target(swzTarget, TARGET_THREAD, THREAD_QUERY_INFORMATION, &hThread);
      if (res != 0)
         goto cleanup;
      if (!OpenThreadToken(hThread, dwRightsRequired, TRUE, phOut))
      {
         res = GetLastError();
         if (res == ERROR_NO_TOKEN)
            _ftprintf(stderr, TEXT(" [!] Error: thread is not impersonating, there is no token to open\n"));
         else
            _ftprintf(stderr, TEXT(" [!] Error: opening thread token failed with code %u\n"), res);
         goto cleanup;
      }
      _tprintf(TEXT(" [.] Operating on impersonation token\n"));
   }
   else if (targetType == TARGET_NT_OBJECT)
   {
      res = open_nt_object(swzTarget, dwRightsRequired, phOut);
      if (res != 0)
      {
         _ftprintf(stderr, TEXT(" [!] Error: opening NT object %s failed with code 0x%08X\n"), swzTarget, res);
         goto cleanup;
      }
   }
   else
   {
      _ftprintf(stderr, TEXT(" [!] Error: no target selected, cannot apply operation\n"));
      res = ERROR_INVALID_PARAMETER;
   }

cleanup:
   return res;
}

int open_nt_directory_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (pUSObjName->Length > sizeof(WCHAR) && pUSObjName->Buffer[(pUSObjName->Length / sizeof(WCHAR)) - 1] == TEXT('\\'))
      pUSObjName->Length -= sizeof(WCHAR);

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   res = NtOpenDirectoryObject(phOut, dwRightsRequired, &objAttr);

   safe_free(pUSObjName);
   return res;
}

int open_nt_file_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   IO_STATUS_BLOCK ioStatus = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   res = NtOpenFile(phOut, dwRightsRequired, &objAttr, &ioStatus, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN_IF);
   
   safe_free(pUSObjName);
   return res;
}

int foreach_nt_object(PCTSTR swzDirectoryNTPath, nt_object_enum_callback_t pCallback, PVOID pData, BOOL bRecurse)
{
   int res = 0;
   HANDLE hDir = INVALID_HANDLE_VALUE;
   ULONG ulBufferSize = 0x1000;
   ULONG ulBufferReq = 0;
   POBJECT_DIRECTORY_INFORMATION pBuffer = (POBJECT_DIRECTORY_INFORMATION)safe_alloc(ulBufferSize);
   ULONG ulContext = 0;
   NTSTATUS status = 0;
   SIZE_T dwChildNTPathLen = _tcslen(swzDirectoryNTPath) + 1000 + 1;
   PTSTR swzChildNTPath = safe_alloc(dwChildNTPathLen * sizeof(TCHAR));
   PTSTR swzChildName = NULL;

   if (swzDirectoryNTPath == NULL || pCallback == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   _tcscpy_s(swzChildNTPath, dwChildNTPathLen, swzDirectoryNTPath);
   if (swzChildNTPath[_tcslen(swzChildNTPath) - 1] != TEXT('\\'))
      _tcscat_s(swzChildNTPath, dwChildNTPathLen, TEXT("\\"));
   swzChildName = swzChildNTPath + _tcslen(swzChildNTPath);

   res = open_nt_directory_object(swzDirectoryNTPath, DIRECTORY_QUERY | DIRECTORY_QUERY, &hDir);
   if (res != 0)
      goto cleanup;

   status = NtQueryDirectoryObject(hDir, (PVOID)pBuffer, ulBufferSize, TRUE, TRUE, &ulContext, &ulBufferReq);
   while (status == 0)
   {
      _tcsncpy_s(swzChildName, 1000, pBuffer->Name.Buffer, pBuffer->Name.Length);
      if (_wcsnicmp(pBuffer->TypeName.Buffer, L"Directory", pBuffer->TypeName.Length / sizeof(WCHAR)) == 0 && bRecurse)
      {
         foreach_nt_object(swzChildNTPath, pCallback, pData, bRecurse);
      }
      res = pCallback(swzChildNTPath, &(pBuffer->TypeName), pData);
      if (res != 0)
         goto cleanup;
      status = NtQueryDirectoryObject(hDir, (PVOID)pBuffer, ulBufferSize, TRUE, FALSE, &ulContext, &ulBufferReq);
   }
   if (status != STATUS_NO_MORE_ENTRIES)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Warning: unable to list contents of NT directory %s, code 0x%08X\n"), swzDirectoryNTPath, status);
      goto cleanup;
   }

   (void)(pCallback);
   (void)(bRecurse);

cleanup:
   if (hDir != INVALID_HANDLE_VALUE && hDir != NULL && !CloseHandle(hDir))
      _ftprintf(stderr, TEXT(" [!] Warning: unable to close NT directory object handle, code %u\n"), GetLastError());
   if (pBuffer != NULL)
      safe_free(pBuffer);
   return res;
}

int foreach_nt_directory_files(PCTSTR swzDirectoryFileNTPath, nt_file_enum_callback_t pCallback, PVOID pData, BOOL bRecurse)
{
   int res = 0;
   HANDLE hDir = INVALID_HANDLE_VALUE;
   ULONG ulFileBufSize = 0x1000;
   PFILE_DIRECTORY_INFORMATION pFile = safe_alloc(ulFileBufSize);
   IO_STATUS_BLOCK ioStatus = { 0 };
   NTSTATUS status = STATUS_SUCCESS;
   SIZE_T dwChildNTPathLen = _tcslen(swzDirectoryFileNTPath) + 1000 + 1;
   PTSTR swzChildNTPath = safe_alloc(dwChildNTPathLen * sizeof(TCHAR));
   PTSTR swzChildName = NULL;

   if (swzDirectoryFileNTPath == NULL || pCallback == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   _tcscpy_s(swzChildNTPath, dwChildNTPathLen, swzDirectoryFileNTPath);
   if (swzChildNTPath[_tcslen(swzChildNTPath) - 1] != TEXT('\\'))
      _tcscat_s(swzChildNTPath, dwChildNTPathLen, TEXT("\\"));
   swzChildName = swzChildNTPath + _tcslen(swzChildNTPath);

   res = open_nt_file_object(swzChildNTPath, FILE_LIST_DIRECTORY | SYNCHRONIZE, &hDir);
   if (res != 0)
      goto cleanup;

   do
   {
      ZeroMemory(&ioStatus, sizeof(ioStatus));
      status = NtQueryDirectoryFile(hDir, NULL, NULL, NULL, &ioStatus, pFile, ulFileBufSize, FileDirectoryInformation, TRUE, NULL, FALSE);
      if (!NT_SUCCESS(status))
      {
         if (status == STATUS_NO_MORE_FILES)
         {
            break;
         }
         else if (status == STATUS_BUFFER_OVERFLOW)
         {
            ulFileBufSize *= 2;
            pFile = safe_realloc(pFile, ulFileBufSize);
            continue;
         }
         _ftprintf(stderr, TEXT(" [!] Warning: querying NT device object '%s' failed with status 0x%08X\n"), swzDirectoryFileNTPath, status);
         goto cleanup;
      }
      else if (WaitForSingleObject(hDir, INFINITE) != WAIT_OBJECT_0)
      {
         _ftprintf(stderr, TEXT(" [!] Warning: failed to wait for NT device object '%s' enum, code %u\n"), swzDirectoryFileNTPath, GetLastError());
         break;
      }
      else if (!NT_SUCCESS(ioStatus._result.Status))
      {
         if (ioStatus._result.Status == STATUS_NO_MORE_FILES)
            break;
         _ftprintf(stderr, TEXT(" [!] Warning: querying NT device object '%s' failed with ioStatus 0x%08X\n"), swzDirectoryFileNTPath, ioStatus._result.Status);
         goto cleanup;
      }
      else if (_wcsnicmp(pFile->FileName, L"..", pFile->FileNameLength / sizeof(WCHAR)) == 0)
      {
         continue;
      }
      _tcsncpy_s(swzChildName, 1000, pFile->FileName, pFile->FileNameLength / sizeof(WCHAR));

      if (bRecurse && (pFile->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
         foreach_nt_directory_files(swzChildNTPath, pCallback, pData, bRecurse);

      res = pCallback(swzChildNTPath, pData);
      if (res != 0)
         goto cleanup;
   }
   while (NT_SUCCESS(status));

cleanup:
   if (hDir != INVALID_HANDLE_VALUE && hDir != NULL && !CloseHandle(hDir))
      _ftprintf(stderr, TEXT(" [!] Warning: failed to close handle %p, code %u\n"), hDir, GetLastError());
   if (pFile != NULL)
      safe_free(pFile);
   return 0;
}

int open_nt_symbolic_link_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenSymbolicLinkObject(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_mutant_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenMutant(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_event_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenEvent(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_keyedevent_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenKeyedEvent(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_section_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenSection(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_semaphore_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenSemaphore(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_timer_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenTimer(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_session_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenSession(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_job_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenJobObject(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_key_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);
   ULONG ulOpenFlags = REG_OPTION_OPEN_LINK; // don't open symbolic link targets, but the links themselves

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   if (has_privilege_caller(SE_BACKUP_NAME) || has_privilege_caller(SE_RESTORE_NAME))
   {
      ulOpenFlags |= REG_OPTION_BACKUP_RESTORE;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenKeyEx(phOut, dwRightsRequired, &objAttr, ulOpenFlags);
   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_filterconnectionport_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   HRESULT hRes = 0;
   PWSTR swzPortName = string_to_wide(swzNTPath);
   DWORD dwGrantedRights = 0;

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   hRes = FilterConnectCommunicationPort(swzPortName, 0, NULL, 0, NULL, phOut);
   if (hRes != S_OK)
   {
      res = hRes;
      goto cleanup;
   }

   if ((dwRightsRequired & MAXIMUM_ALLOWED) == 0)
   {
      res = get_handle_granted_rights(*phOut, &dwGrantedRights);
      if (res != 0)
         goto cleanup;

      if ((dwGrantedRights & dwRightsRequired) != dwRightsRequired)
         res = ERROR_ACCESS_DENIED;
   }

cleanup:
   if (res != 0 && *phOut != NULL && *phOut != INVALID_HANDLE_VALUE)
      CloseHandle(*phOut);
   if (swzPortName != NULL)
      safe_free(swzPortName);
   return res;
}

int open_nt_alpcconnectionport_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);
   OBJECT_ATTRIBUTES objAttr = { 0 };
   LARGE_INTEGER liTimeout = { 0 };
   ULONG ulBufferLen = 0;
   DWORD dwGrantedRights = 0;

   if (swzNTPath == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
   liTimeout.QuadPart = 1;
   status = NtAlpcConnectPort(phOut, pUSObjName, &objAttr, NULL, 0, NULL, NULL, &ulBufferLen, NULL, NULL, &liTimeout);
   if (!NT_SUCCESS(res))
   {
      res = status;
      goto cleanup;
   }

   if ((dwRightsRequired & MAXIMUM_ALLOWED) == 0)
   {
      res = get_handle_granted_rights(*phOut, &dwGrantedRights);
      if (res != 0)
         goto cleanup;

      if ((dwGrantedRights & dwRightsRequired) != dwRightsRequired)
         res = ERROR_ACCESS_DENIED;
   }

cleanup:
   if (res != 0 && *phOut != NULL && *phOut != INVALID_HANDLE_VALUE)
      CloseHandle(*phOut);
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int open_nt_unsupported_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   UNREFERENCED_PARAMETER(swzNTPath);
   UNREFERENCED_PARAMETER(dwRightsRequired);
   UNREFERENCED_PARAMETER(phOut);
   return ERROR_NOT_SUPPORTED;
}

int open_nt_object_with_type(PCTSTR swzNTPath, PCTSTR swzType, DWORD dwRightsRequired, HANDLE *phOut)
{
   for (SIZE_T i = 0; pNTObjectTypes[i][0] != NULL; i++)
   {
      if (_tcsicmp((PCTSTR)pNTObjectTypes[i][0], swzType) == 0)
      {
         return pNTObjectTypes[i][1](swzNTPath, dwRightsRequired, phOut);
      }
   }
   _ftprintf(stderr, TEXT(" [!] Warning: skipping unsupported NT object type %s (cannot open %s)\n"), swzType, swzNTPath);
   return ERROR_NOT_SUPPORTED;
}

int get_handle_granted_rights(HANDLE hHandle, PDWORD pdwGrantedRights)
{
   int res = 0;
   NTSTATUS status = 0;
   ULONG ulBufRequired = 0;
   ULONG ulBufLen = 0x1000;
   PSYSTEM_HANDLE_INFORMATION pHandles = safe_alloc(ulBufLen);
   BOOL bFound = FALSE;

   if (pdwGrantedRights == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   do
   {
      ulBufLen *= 2;
      pHandles = safe_realloc(pHandles, ulBufLen);
      status = NtQuerySystemInformation(SystemHandleInformation, pHandles, ulBufLen, &ulBufRequired);
      // NtQuerySystemInformation(SystemHandleInformation) doesn't fill ulBufRequired: try again with a higher guess...
   }
   while (status == STATUS_INFO_LENGTH_MISMATCH);

   if (!NT_SUCCESS(status))
   {
      res = status;
      goto cleanup;
   }

   for (ULONG i = 0; i < pHandles->HandleCount; i++)
   {
      PSYSTEM_HANDLE_TABLE_ENTRY_INFO pHandle = &(pHandles->Handles[i]);
      if (pHandle->ProcessId == GetCurrentProcessId() && (ULONG)pHandle->Handle == (ULONG)hHandle)
      {
         bFound = TRUE;
         *pdwGrantedRights = pHandle->GrantedAccess;
         break;
      }
   }

   if (!bFound)
      res = ERROR_NOT_FOUND;

cleanup:
   safe_free(pHandles);
   return res;
}

static int callback_find_nt_object_type(PCTSTR swzNTPath, PUNICODE_STRING usObjType, PVOID pData)
{
   nt_object_lookup_t *pLookup = (nt_object_lookup_t*)pData;
   if (_tcscmp(swzNTPath, pLookup->swzNTPath) == 0)
   {
      pLookup->bFound = TRUE;
      pLookup->swzType = unicode_to_string(usObjType);
      return 1; // stop enumerating
   }
   else
   {
      return 0;
   }
}

int open_nt_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   SIZE_T dwNTPathLen = 0;
   PTSTR swzNTDirPath = NULL;
   nt_object_lookup_t lookup = { 0 };

   if (swzNTPath == NULL || phOut == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }
   else if (*swzNTPath != TEXT('\\'))
   {
      _ftprintf(stderr, TEXT(" [!] Error: for kernel objects, an absolute NT path is required.\n"));
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   dwNTPathLen = _tcslen(swzNTPath);
   if (swzNTPath[dwNTPathLen - 1] == TEXT('\\'))
   {
      _tprintf(TEXT(" [.] Operating on NT directory %s\n"), swzNTPath);
      res = open_nt_directory_object(swzNTPath, dwRightsRequired, phOut);
   }
   else
   {
      lookup.bFound = FALSE;
      lookup.swzNTPath = swzNTPath;
      swzNTDirPath = safe_strdup(swzNTPath);
      basedir(swzNTDirPath);
      foreach_nt_object(swzNTDirPath, callback_find_nt_object_type, &lookup, FALSE);
      if (!lookup.bFound)
      {
         _ftprintf(stderr, TEXT(" [!] Warning: object %s not found in %s\n"), swzNTPath, swzNTDirPath);
         res = ERROR_NOT_FOUND;
         goto cleanup;
      }
      _tprintf(TEXT(" [.] Operating on NT object %s of type %s\n"), swzNTPath, lookup.swzType);
      res = open_nt_object_with_type(swzNTPath, lookup.swzType, dwRightsRequired, phOut);
   }

cleanup:
   if (swzNTDirPath != NULL)
      safe_free(swzNTDirPath);
   if (lookup.swzType != NULL)
      safe_free(lookup.swzType);
   return res;
}

static int nt_object_callback(PCTSTR swzNTPath, PUNICODE_STRING usObjType, PVOID pData)
{
   int res = 0;
   DWORD dwDesiredAccess = *(PDWORD)pData;
   PTSTR swzType = unicode_to_string(usObjType);
   HANDLE hObj = INVALID_HANDLE_VALUE;

   res = open_nt_object_with_type(swzNTPath, swzType, dwDesiredAccess, &hObj);
   if (res == 0)
   {
      _tprintf(TEXT("%20s | %s\n"), swzType, swzNTPath);
      CloseHandle(hObj);
   }
   else if (res != STATUS_ACCESS_DENIED && res != ERROR_NOT_SUPPORTED && res != 0x80070005) // TODO: migrate nt_object_open_t to return a HRESULT
   {
      _tprintf(TEXT(" [!] Warning: failed to open NT object %s (%s) : code 0x%08X\n"), swzNTPath, swzType, res);
   }
   return 0;
}

int enumerate_nt_objects_with(DWORD dwDesiredAccess)
{
   return foreach_nt_object(TEXT("\\"), nt_object_callback, &dwDesiredAccess, TRUE);
}