#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include\files.h"
#include "include\nt.h"
#include "include\token.h"
#include "include\utils.h"

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