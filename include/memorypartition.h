#pragma once
#include <Windows.h>

int open_nt_partition_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
