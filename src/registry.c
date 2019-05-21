#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\registry.h"
#include "include\nt.h"
#include "include\token.h"
#include "include\utils.h"

int open_nt_key_object(PCTSTR swzNTorWin32Path, target_t *pTargetType, DWORD dwRightsRequired, HANDLE *phOut)
{
   UNREFERENCED_PARAMETER(pTargetType);
   int res = 0;
   NTSTATUS status = 0;
   PCTSTR swzWin32Path = NULL;
   OBJECT_ATTRIBUTES objAttr = { 0 };
   PUNICODE_STRING pUSObjName = NULL;
   ULONG ulOpenFlags = REG_OPTION_OPEN_LINK; // don't open symbolic link targets, but the links themselves
   HKEY hRoot = NULL;

   if (swzNTorWin32Path == NULL || phOut == NULL || (*phOut != NULL && *phOut != INVALID_HANDLE_VALUE))
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }
   
   if (str_starts_with(swzNTorWin32Path, TEXT("HKEY_CLASSES_ROOT")))
   {
      hRoot = HKEY_CLASSES_ROOT;
      swzWin32Path = swzNTorWin32Path + _tcslen(TEXT("HKEY_CLASSES_ROOT"));
   }
   else if (str_starts_with(swzNTorWin32Path, TEXT("HKEY_CURRENT_CONFIG")))
   {
      hRoot = HKEY_CURRENT_CONFIG;
      swzWin32Path = swzNTorWin32Path + _tcslen(TEXT("HKEY_CURRENT_CONFIG"));
   }
   else if (str_starts_with(swzNTorWin32Path, TEXT("HKEY_CURRENT_USER")))
   {
      hRoot = HKEY_CURRENT_USER;
      swzWin32Path = swzNTorWin32Path + _tcslen(TEXT("HKEY_CURRENT_USER"));
   }
   else if (str_starts_with(swzNTorWin32Path, TEXT("HKCU")))
   {
      hRoot = HKEY_CURRENT_USER;
      swzWin32Path = swzNTorWin32Path + _tcslen(TEXT("HKCU"));
   }
   else if (str_starts_with(swzNTorWin32Path, TEXT("HKLM")))
   {
      hRoot = HKEY_LOCAL_MACHINE;
      swzWin32Path = swzNTorWin32Path + _tcslen(TEXT("HKLM"));
   }
   else if (str_starts_with(swzNTorWin32Path, TEXT("HKEY_LOCAL_MACHINE")))
   {
      hRoot = HKEY_LOCAL_MACHINE;
      swzWin32Path = swzNTorWin32Path + _tcslen(TEXT("HKEY_LOCAL_MACHINE"));
   }
   else if (str_starts_with(swzNTorWin32Path, TEXT("HKEY_LOCAL_MACHINE")))
   {
      hRoot = HKEY_LOCAL_MACHINE;
      swzWin32Path = swzNTorWin32Path + _tcslen(TEXT("HKEY_LOCAL_MACHINE"));
   }
   else if (str_starts_with(swzNTorWin32Path, TEXT("HKEY_USERS")))
   {
      hRoot = HKEY_USERS;
      swzWin32Path = swzNTorWin32Path + _tcslen(TEXT("HKEY_USERS"));
   }

   // Strip any leading '\'
   if (swzWin32Path != NULL && *swzWin32Path == TEXT('\\'))
      swzWin32Path++;
   
   // Is it a Win32 path?
   if (swzWin32Path != NULL)
   {
      //TODO: replace with a nice formatting directly to NT path, avoid Win32 APi
      res = RegOpenKeyEx(hRoot, swzWin32Path, REG_OPTION_OPEN_LINK, dwRightsRequired, (PHKEY)phOut);
   }
   // Otherwise, it must be a NT absolute path
   else
   {
      pUSObjName = string_to_unicode(swzNTorWin32Path);
      if (has_privilege_caller(SE_BACKUP_NAME) || has_privilege_caller(SE_RESTORE_NAME))
      {
         ulOpenFlags |= REG_OPTION_BACKUP_RESTORE;
      }
      InitializeObjectAttributes(&objAttr, pUSObjName, 0, NULL, NULL);
      status = NtOpenKeyEx(phOut, dwRightsRequired, &objAttr, ulOpenFlags);
      if (!NT_SUCCESS(status))
         res = status;
   }

cleanup:
   if (pUSObjName != NULL)
      safe_free(pUSObjName);
   return res;
}

int foreach_nt_key(PCTSTR swzKeyNTPath, nt_path_enum_callback_t pCallback, PVOID pData, BOOL bRecurse)
{
   int res = 0;
   BOOL bImpersonating = FALSE;
   HANDLE hKey = INVALID_HANDLE_VALUE;
   target_t targetType = TARGET_REGKEY;
   NTSTATUS status = 0;
   ULONG ulIndex = 0;
   ULONG ulBufLen = 0x1000;
   ULONG ulBufRequired = 0;
   PKEY_BASIC_INFORMATION pKeyItem = safe_alloc(ulBufLen);
   SIZE_T dwChildNTPathLen = 0;
   PTSTR swzChildNTPath = NULL;
   PTSTR swzChildName = NULL;

   if (swzKeyNTPath == NULL || pCallback == NULL)
   {
      res = ERROR_INVALID_PARAMETER;
      goto cleanup;
   }

   dwChildNTPathLen = _tcslen(swzKeyNTPath) + 1000 + 1;
   swzChildNTPath = safe_alloc(dwChildNTPathLen * sizeof(TCHAR));
   _tcscpy_s(swzChildNTPath, dwChildNTPathLen, swzKeyNTPath);
   if (swzChildNTPath[_tcslen(swzChildNTPath) - 1] != TEXT('\\'))
      _tcscat_s(swzChildNTPath, dwChildNTPathLen, TEXT("\\"));
   swzChildName = swzChildNTPath + _tcslen(swzChildNTPath);

   // Open registry keys all the way doing impersonation, but only
   // if there's an impersonation token set up and it doesn't have
   // the SeChangeNotifyPrivilege, which allows bypassing access checks
   // on intermediary keys. If it has that privilege, consider it can
   // open the key anyway (e.g. by "guessing" its path) and do the
   // enumeration part without impersonating.
   if (!has_privilege_impersonated_target(SE_CHANGE_NOTIFY_NAME))
   {
      res = start_impersonated_operation();
      if (res != 0)
         goto cleanup;
      bImpersonating = TRUE;
   }

   res = open_nt_key_object(swzKeyNTPath, &targetType, KEY_ENUMERATE_SUB_KEYS, &hKey);

   if (bImpersonating)
   {
      int res2 = end_impersonated_operation();
      if (res == 0)
         res = res2;
   }

   if (res != 0)
      goto cleanup;

   do
   {
      status = NtEnumerateKey(hKey, ulIndex, KeyBasicInformation, pKeyItem, ulBufLen, &ulBufRequired);
      if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL)
      {
         ulBufLen = ulBufRequired;
         pKeyItem = safe_realloc(pKeyItem, ulBufLen);
         continue;
      }
      else if (!NT_SUCCESS(status))
      {
         break;
      }

      //FIXME: support for !UNICODE
      _tcsncpy_s(swzChildName, 1000, pKeyItem->Name, pKeyItem->NameLength / sizeof(WCHAR));

      if (bRecurse)
         foreach_nt_key(swzChildNTPath, pCallback, pData, bRecurse);

      res = pCallback(swzChildNTPath, pData);
      if (res != 0)
         goto cleanup;

      ulIndex++;
   } while (NT_SUCCESS(status));

   if (status != STATUS_NO_MORE_ENTRIES)
      res = status;

cleanup:
   if (hKey != INVALID_HANDLE_VALUE)
      CloseHandle(hKey);
   if (swzChildNTPath != NULL)
      safe_free(swzChildNTPath);
   if (pKeyItem != NULL)
      safe_free(pKeyItem);
   return res;
}

static int nt_key_callback(PCTSTR swzKeyNTPath, PVOID pData)
{
   int res = 0;
   DWORD dwDesiredAccess = *(PDWORD)pData;
   HANDLE hKey = INVALID_HANDLE_VALUE;
   target_t targetType = TARGET_REGKEY;

   res = start_impersonated_operation();
   if (res != 0)
      goto cleanup;

   res = open_nt_key_object(swzKeyNTPath, &targetType, dwDesiredAccess, &hKey);
   if (res == 0)
   {
      _tprintf(TEXT("%s\n"), swzKeyNTPath);
      if (!CloseHandle(hKey))
         _ftprintf(stderr, TEXT(" [!] Warning: could not close handle to registry key %s during enumeration, code %u"), swzKeyNTPath, GetLastError());
   }

   res = end_impersonated_operation();
   if (res != 0)
      goto cleanup;

cleanup:
   return 0;
}

int enumerate_keys_with(DWORD dwDesiredAccess)
{
   return foreach_nt_key(TEXT("\\REGISTRY"), nt_key_callback, &dwDesiredAccess, TRUE);
}