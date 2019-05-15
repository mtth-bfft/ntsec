#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\registry.h"
#include "include\nt.h"
#include "include\token.h"
#include "include\utils.h"

int open_regkey_by_name(PCTSTR swzRegKey, REGSAM ulDesiredAccess, PHKEY phOut)
{
   int res = 0;
   HKEY hRoot = NULL;

   if (str_starts_with(swzRegKey, TEXT("HKEY_CLASSES_ROOT")))
   {
      hRoot = HKEY_CLASSES_ROOT;
      swzRegKey += _tcslen(TEXT("HKEY_CLASSES_ROOT"));
   }
   else if (str_starts_with(swzRegKey, TEXT("HKEY_CURRENT_CONFIG")))
   {
      hRoot = HKEY_CURRENT_CONFIG;
      swzRegKey += _tcslen(TEXT("HKEY_CURRENT_CONFIG"));
   }
   else if (str_starts_with(swzRegKey, TEXT("HKEY_CURRENT_USER")))
   {
      hRoot = HKEY_CURRENT_USER;
      swzRegKey += _tcslen(TEXT("HKEY_CURRENT_USER"));
   }
   else if (str_starts_with(swzRegKey, TEXT("HKCU")))
   {
      hRoot = HKEY_CURRENT_USER;
      swzRegKey += _tcslen(TEXT("HKCU"));
   }
   else if (str_starts_with(swzRegKey, TEXT("HKLM")))
   {
      hRoot = HKEY_LOCAL_MACHINE;
      swzRegKey += _tcslen(TEXT("HKLM"));
   }
   else if (str_starts_with(swzRegKey, TEXT("HKEY_LOCAL_MACHINE")))
   {
      hRoot = HKEY_LOCAL_MACHINE;
      swzRegKey += _tcslen(TEXT("HKEY_LOCAL_MACHINE"));
   }
   else if (str_starts_with(swzRegKey, TEXT("HKEY_LOCAL_MACHINE")))
   {
      hRoot = HKEY_LOCAL_MACHINE;
      swzRegKey += _tcslen(TEXT("HKEY_LOCAL_MACHINE"));
   }
   else if (str_starts_with(swzRegKey, TEXT("HKEY_USERS")))
   {
      hRoot = HKEY_USERS;
      swzRegKey += _tcslen(TEXT("HKEY_USERS"));
   }
   else
   {
      //TODO: fallback to raw NT path within \REGISTRY
      res = ERROR_INVALID_PARAMETER;
      _ftprintf(stderr, TEXT(" [!] Cannot open registry key with unknown hive name '%s'\n"), swzRegKey);
      goto cleanup;
   }

   if (swzRegKey[0] == TEXT('\\'))
      swzRegKey++;

   res = RegOpenKeyEx(hRoot, swzRegKey, REG_OPTION_OPEN_LINK, ulDesiredAccess, phOut);
   if (res != ERROR_SUCCESS)
      _ftprintf(stderr, TEXT(" [!] Failed to open registry key '%s', code %u\n"), swzRegKey, res);

cleanup:
   return res;
}

static int nt_key_callback(PCTSTR swzKeyNTPath, PVOID pData)
{
   int res = 0;
   DWORD dwDesiredAccess = *(PDWORD)pData;
   HANDLE hKey = INVALID_HANDLE_VALUE;

   res = start_impersonated_operation();
   if (res != 0)
      goto cleanup;

   res = open_nt_key_object(swzKeyNTPath, dwDesiredAccess, &hKey);
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