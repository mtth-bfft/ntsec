#pragma once
#include <Windows.h>

int open_nt_timer_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
