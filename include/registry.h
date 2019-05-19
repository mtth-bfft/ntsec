#pragma once
#include <Windows.h>
#include "include\nt.h"

int open_nt_key_object(PCTSTR swzNTorWin32Path, DWORD dwRightsRequired, HANDLE *phOut);
int enumerate_keys_with(DWORD dwDesiredAccess);
int foreach_nt_key(HANDLE hKey, nt_path_enum_callback_t pCallback, PVOID pData, BOOL bRecurse);
