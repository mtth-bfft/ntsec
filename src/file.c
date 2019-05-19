#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\file.h"
#include "include\nt.h"
#include "include\directory.h"
#include "include\token.h"
#include "include\utils.h"

int open_nt_file_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
{
   int res = 0;
   NTSTATUS status = 0;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   IO_STATUS_BLOCK ioStatus = { 0 };
   LARGE_INTEGER liInitialSize = { 0 };
   PUNICODE_STRING pUSObjName = string_to_unicode(swzNTPath);

   if (phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtCreateFile(phOut, dwRightsRequired, &objAttr, &ioStatus, &liInitialSize, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, NULL, 0);
   if (!NT_SUCCESS(status))
      res = status;

cleanup:
   safe_free(pUSObjName);
   return res;
}

int foreach_nt_file(PCTSTR swzDirectoryFileNTPath, nt_path_enum_callback_t pCallback, PVOID pData, BOOL bRecurse)
{
   int res = 0;
   BOOL bImpersonating = FALSE;
   HANDLE hDir = INVALID_HANDLE_VALUE;
   ULONG ulFileBufSize = 0x1000;
   PFILE_DIRECTORY_INFORMATION pFile = safe_alloc(ulFileBufSize);
   IO_STATUS_BLOCK ioStatus = { 0 };
   NTSTATUS status = STATUS_SUCCESS;
   SIZE_T dwChildNTPathLen = 0;
   PTSTR swzChildNTPath = NULL;
   PTSTR swzChildName = NULL;

   if (swzDirectoryFileNTPath == NULL || pCallback == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   dwChildNTPathLen = _tcslen(swzDirectoryFileNTPath) + 1000 + 1;
   swzChildNTPath = safe_alloc(dwChildNTPathLen * sizeof(TCHAR));
   _tcscpy_s(swzChildNTPath, dwChildNTPathLen, swzDirectoryFileNTPath);
   if (swzChildNTPath[_tcslen(swzChildNTPath) - 1] != TEXT('\\'))
      _tcscat_s(swzChildNTPath, dwChildNTPathLen, TEXT("\\"));
   swzChildName = swzChildNTPath + _tcslen(swzChildNTPath);

   // Open directories all the way doing impersonation, but only
   // if there's an impersonation token set up and it doesn't have
   // the SeChangeNotifyPrivilege, which allows bypassing access checks
   // on intermediary dirs. If it has that privilege, consider it can
   // open the file anyway (e.g. by "guessing" its path) and do the
   // enumeration part without impersonating.
   if (!has_privilege_impersonated_target(SE_CHANGE_NOTIFY_NAME))
   {
      res = start_impersonated_operation();
      if (res != 0)
         goto cleanup;
      bImpersonating = TRUE;
   }

   res = open_nt_file_object(swzChildNTPath, FILE_LIST_DIRECTORY | SYNCHRONIZE, &hDir);

   if (bImpersonating)
   {
      int res2 = end_impersonated_operation();
      if (res2 != 0)
      {
         if (res == 0)
            res = res2;
         goto cleanup;
      }
   }

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
         _ftprintf(stderr, TEXT(" [!] Warning: querying NT directory file object '%s' failed with status 0x%08X\n"), swzDirectoryFileNTPath, status);
         goto cleanup;
      }
      else if (WaitForSingleObject(hDir, INFINITE) != WAIT_OBJECT_0)
      {
         _ftprintf(stderr, TEXT(" [!] Warning: failed to wait for NT directory file object '%s' enum, code %u\n"), swzDirectoryFileNTPath, GetLastError());
         break;
      }
      else if (!NT_SUCCESS(ioStatus._result.Status))
      {
         if (ioStatus._result.Status == STATUS_NO_MORE_FILES)
            break;
         _ftprintf(stderr, TEXT(" [!] Warning: querying NT directory file object '%s' failed with ioStatus 0x%08X\n"), swzDirectoryFileNTPath, ioStatus._result.Status);
         goto cleanup;
      }
      else if (_wcsnicmp(pFile->FileName, L"..", pFile->FileNameLength / sizeof(WCHAR)) == 0)
      {
         continue;
      }
      //FIXME: support for !UNICODE
      _tcsncpy_s(swzChildName, 1000, pFile->FileName, pFile->FileNameLength / sizeof(WCHAR));

      if (bRecurse && (pFile->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
         foreach_nt_file(swzChildNTPath, pCallback, pData, bRecurse);

      res = pCallback(swzChildNTPath, pData);
      if (res != 0)
         goto cleanup;
   } while (NT_SUCCESS(status));

cleanup:
   if (hDir != INVALID_HANDLE_VALUE && hDir != NULL && !CloseHandle(hDir))
      _ftprintf(stderr, TEXT(" [!] Warning: failed to close handle %p, code %u\n"), hDir, GetLastError());
   if (pFile != NULL)
      safe_free(pFile);
   return 0;
}

static int nt_file_callback(PCTSTR swzFileNTPath, PVOID pData)
{
   int res = 0;
   int res2 = 0;
   DWORD dwDesiredAccess = *(PDWORD)pData;
   HANDLE hFile = INVALID_HANDLE_VALUE;

   res = start_impersonated_operation();
   if (res != 0)
      goto cleanup;

   res = open_nt_file_object(swzFileNTPath, dwDesiredAccess, &hFile);
   if (res == 0)
   {
      _tprintf(TEXT("%s\n"), swzFileNTPath);
      if (!CloseHandle(hFile))
         _ftprintf(stderr, TEXT(" [!] Warning: could not close file handle to %s during enumeration, code %u\n"), swzFileNTPath, GetLastError());
   }
   else if (res != STATUS_ACCESS_DENIED)
   {
      _ftprintf(stderr, TEXT(" [!] Warning: opening NT file object '%s' failed with code 0x%08X\n"), swzFileNTPath, res);
   }

   res2 = end_impersonated_operation();
   if (res2 != 0)
   {
      if (res == 0)
         res = res2;
      goto cleanup;
   }

cleanup:
   return 0; // Always return 0 to continue enumerating
}

static int nt_named_pipe_callback(PCTSTR swzFileNTPath, PVOID pData)
{
   int res = 0;
   int res2 = 0;
   DWORD dwDesiredAccess = *(PDWORD)pData;
   HANDLE hFile = INVALID_HANDLE_VALUE;

   res = start_impersonated_operation();
   if (res != 0)
      goto cleanup;

   res = open_nt_file_object(swzFileNTPath, dwDesiredAccess, &hFile);
   if (res == 0)
   {
      if (_tcsnicmp(TEXT("\\Device\\NamedPipe\\"), swzFileNTPath, 18) == 0)
         swzFileNTPath += 18;
      _tprintf(TEXT("%s\n"), swzFileNTPath);
      if (!CloseHandle(hFile))
         _ftprintf(stderr, TEXT(" [!] Warning: could not close file handle to %s during enumeration, code %u\n"), swzFileNTPath, GetLastError());
   }
   else if (res != STATUS_ACCESS_DENIED)
   {
      _ftprintf(stderr, TEXT(" [!] Warning: opening NT file object '%s' failed with code 0x%08X\n"), swzFileNTPath, res);
   }

   res2 = end_impersonated_operation();
   if (res2 != 0)
   {
      if (res == 0)
         res = res2;
      goto cleanup;
   }

cleanup:
   return 0; // Always return 0 to continue enumerating
}

static int nt_device_callback(PCTSTR swzDeviceNTPath, PUNICODE_STRING pusObjType, PVOID pData)
{
   if (_wcsnicmp(pusObjType->Buffer, L"Device", pusObjType->Length) != 0)
      return 0;
   return foreach_nt_file(swzDeviceNTPath, nt_file_callback, pData, TRUE);
}

int enumerate_files_with(PCTSTR swzBaseNTPath, DWORD dwDesiredAccess)
{
   int res = 0;

   _tprintf(TEXT(" [.] Files in %s with access 0x%08X\n"), swzBaseNTPath, dwDesiredAccess);

   // In case we got passed a NT directory object path
   res = foreach_nt_object(swzBaseNTPath, nt_device_callback, (PVOID)&dwDesiredAccess, TRUE);
   if (res == 0)
      return res;

   // In case we got passed a NT directory file path directly
   printf(" [.] Enumerated devices and files within devices:\n");
   res = foreach_nt_file(swzBaseNTPath, nt_file_callback, (PVOID)&dwDesiredAccess, TRUE);

   return res;
}

int enumerate_namedpipes_with(DWORD dwDesiredAccess)
{
   int res = 0;
   _tprintf(TEXT(" [.] Named pipes with access 0x%08X\n"), dwDesiredAccess);
   res = foreach_nt_file(TEXT("\\Device\\NamedPipe\\"), nt_named_pipe_callback, (PVOID)&dwDesiredAccess, TRUE);
   return res;
}