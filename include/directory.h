#pragma once
#include <Windows.h>
#include "include\nt.h"

typedef int(*nt_object_enum_callback_t)(PCTSTR swzNTPath, PUNICODE_STRING usObjType, PVOID pData);

int open_nt_directory_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
int foreach_nt_object(PCTSTR swzNTPath, nt_object_enum_callback_t pCallback, PVOID pData, BOOL bRecurse);
int enumerate_nt_objects_with(DWORD dwDesiredAccess);
