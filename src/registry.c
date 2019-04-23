#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "registry.h"
#include "utils.h"

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