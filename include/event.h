#pragma once
#include <Windows.h>

int open_nt_event_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
