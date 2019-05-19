#pragma once
#include <Windows.h>

int open_nt_filterconnectionport_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
