#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "files.h"
#include "nt.h"
#include "utils.h"

static int nt_file_callback(PCTSTR swzFileNTPath, PVOID pData)
{
   DWORD dwDesiredAccess = *(PDWORD)pData;
   (void)(dwDesiredAccess);
   _tprintf(TEXT("%s\n"), swzFileNTPath);
   return 0;
}

static int nt_device_callback(PCTSTR swzDeviceNTPath, PUNICODE_STRING pusObjType, PVOID pData)
{
   if (_wcsnicmp(pusObjType->Buffer, L"Device", pusObjType->Length) != 0)
      return 0;
   return foreach_nt_directory_files(swzDeviceNTPath, nt_file_callback, pData, TRUE);
}

int enumerate_files_with(DWORD dwDesiredAccess)
{
   // Enumerate accessible disks (some might not have a DOS letter and only be accessible through native calls)
   // and then foreach disk, enumerate files
   return foreach_nt_object(TEXT("\\"), nt_device_callback, (PVOID)&dwDesiredAccess, TRUE);
}