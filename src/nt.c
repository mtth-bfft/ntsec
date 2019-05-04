#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
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

PVOID pNTObjectTypes[][2] = {
   { TEXT("Directory"), (PVOID)&open_nt_directory_object },
   { NULL,              NULL}
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

int resolve_imports()
{
   int res = 0;

   HMODULE hNTDLL = LoadLibrary(TEXT("ntdll.dll"));
   if (hNTDLL == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic imports, NTDLL load failed with code '%u'\n"), res);
      goto cleanup;
   }
   NtOpenDirectoryObject = (PNtOpenDirectoryObject)GetProcAddress(hNTDLL, "NtOpenDirectoryObject");
   if (NtOpenDirectoryObject == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic import NtOpenDirectoryObject, failed with code '%u'\n"), res);
      goto cleanup;
   }
   NtQueryDirectoryObject = (PNtQueryDirectoryObject)GetProcAddress(hNTDLL, "NtQueryDirectoryObject");
   if (NtQueryDirectoryObject == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic import NtQueryDirectoryObject, failed with code '%u'\n"), res);
      goto cleanup;
   }
   NtOpenFile = (PNtOpenFile)GetProcAddress(hNTDLL, "NtOpenFile");
   if (NtOpenFile == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic import NtOpenFile, failed with code '%u'\n"), res);
      goto cleanup;
   }
   NtQueryDirectoryFile = (PNtQueryDirectoryFile)GetProcAddress(hNTDLL, "NtQueryDirectoryFile");
   if (NtQueryDirectoryFile == NULL)
   {
      res = GetLastError();
      _ftprintf(stderr, TEXT(" [!] Error: cannot resolve dynamic import NtQueryDirectoryFile, failed with code '%u'\n"), res);
      goto cleanup;
   }

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
         goto cleanup;
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
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (pUSObjName->Length > sizeof(WCHAR) && pUSObjName->Buffer[(pUSObjName->Length / sizeof(WCHAR)) - 1] == TEXT('\\'))
      pUSObjName->Length -= sizeof(WCHAR);

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenDirectoryObject(phOut, dwRightsRequired, &objAttr);
   if (status != STATUS_SUCCESS)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Warning: opening NT directory object '%.*ws' failed with status 0x%08X\n"), pUSObjName->Length, pUSObjName->Buffer, res);
   }

   safe_free(pUSObjName);
   return res;
}

int open_nt_file_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   IO_STATUS_BLOCK ioStatus = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenFile(phOut, dwRightsRequired, &objAttr, &ioStatus, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN_IF);
   if (status != STATUS_SUCCESS)
   {
      res = status;
      _ftprintf(stderr, TEXT(" [!] Warning: opening NT file object '%.*ws' failed with status 0x%08X\n"), pUSObjName->Length, pUSObjName->Buffer, res);
   }

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

int open_nt_object_with_type(PCTSTR swzNTPath, PCTSTR swzType, DWORD dwRightsRequired, HANDLE *phOut)
{
   if (_tcsicmp(swzType, TEXT("Device")) == 0)
      return open_nt_file_object(swzNTPath, dwRightsRequired, phOut);
   else
   {
      _ftprintf(stderr, TEXT(" [!] Warning: cannot open unsupported NT object type %s (at %s)\n"), swzType, swzNTPath);
      return ERROR_NOT_SUPPORTED;
   }
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

/*
static int nt_object_callback(PCTSTR swzNTPath, PUNICODE_STRING usObjType, PVOID pData)
{
   int res = 0;


}

int enumerate_nt_objects_with(DWORD dwDesiredAccess)
{
   return foreach_nt_object(TEXT("\\"), nt_object_callback, &dwDesiredAccess, TRUE);
}*/