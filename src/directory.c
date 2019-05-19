#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\directory.h"
#include "include\nt.h"
#include "include\token.h"
#include "include\targets.h"
#include "include\utils.h"

int open_nt_directory_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut)
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

   if (pUSObjName->Length > sizeof(WCHAR) && pUSObjName->Buffer[(pUSObjName->Length / sizeof(WCHAR)) - 1] == TEXT('\\'))
      pUSObjName->Length -= sizeof(WCHAR);

   InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
   status = NtOpenDirectoryObject(phOut, dwRightsRequired, &objAttr);
   if (!NT_SUCCESS(status))
      res = status;

cleanup:
   safe_free(pUSObjName);
   return res;
}

int foreach_nt_object(PCTSTR swzDirectoryNTPath, nt_object_enum_callback_t pCallback, PVOID pData, BOOL bRecurse)
{
   int res = 0;
   BOOL bImpersonating = FALSE;
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

   res = open_nt_directory_object(swzDirectoryNTPath, DIRECTORY_QUERY | DIRECTORY_QUERY, &hDir);
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
   {
      _ftprintf(stderr, TEXT(" [!] Warning: opening NT directory object %s failed with code 0x%08X\n"), swzDirectoryNTPath, res);
      goto cleanup;
   }

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

cleanup:
   if (hDir != INVALID_HANDLE_VALUE && hDir != NULL && !CloseHandle(hDir))
      _ftprintf(stderr, TEXT(" [!] Warning: unable to close NT directory object handle, code %u\n"), GetLastError());
   if (pBuffer != NULL)
      safe_free(pBuffer);
   return res;
}

static int nt_object_callback(PCTSTR swzNTPath, PUNICODE_STRING usObjType, PVOID pData)
{
   int res = 0;
   DWORD dwDesiredAccess = *(PDWORD)pData;
   PTSTR swzType = unicode_to_string(usObjType);
   HANDLE hObj = INVALID_HANDLE_VALUE;

   res = open_target_by_typename(swzNTPath, usObjType->Buffer, usObjType->Length, dwDesiredAccess, &hObj);
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
