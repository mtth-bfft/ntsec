#pragma once
#include <Windows.h>
#include "include\nt.h"
#include "include\targets.h"

int open_nt_file_object(PCTSTR swzNTPath, target_t *pTargetType, DWORD dwRightsRequired, HANDLE *phOut);
int foreach_nt_file(PCTSTR swzDirectoryFileNTPath, nt_path_enum_callback_t pCallback, PVOID pData, BOOL bRecurse);
int enumerate_files_with(PCTSTR swzBaseNTPath, DWORD dwDesiredAccess);
int enumerate_namedpipes_with(DWORD dwDesiredAccess);
