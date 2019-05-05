#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "files.h"
#include "nt.h"
#include "utils.h"

static int nt_file_callback(PCTSTR swzFileNTPath, PVOID pData)
{
   int res = 0;
   DWORD dwDesiredAccess = *(PDWORD)pData;
   HANDLE hFile = INVALID_HANDLE_VALUE;

   res = open_nt_file_object(swzFileNTPath, dwDesiredAccess, &hFile);
   if (res == 0)
   {
      _tprintf(TEXT("%s\n"), swzFileNTPath);
      if (!CloseHandle(hFile))
         _ftprintf(stderr, TEXT(" [!] Warning: could not close file handle to %s during enumeration, code %u"), swzFileNTPath, GetLastError());
   }

   return 0;
}

static int nt_device_callback(PCTSTR swzDeviceNTPath, PUNICODE_STRING pusObjType, PVOID pData)
{
   if (_wcsnicmp(pusObjType->Buffer, L"Device", pusObjType->Length) != 0)
      return 0;
   return foreach_nt_file(swzDeviceNTPath, nt_file_callback, pData, TRUE);
}

int enumerate_files_with(DWORD dwDesiredAccess)
{
   return foreach_nt_object(TEXT("\\"), nt_device_callback, (PVOID)&dwDesiredAccess, TRUE);
}