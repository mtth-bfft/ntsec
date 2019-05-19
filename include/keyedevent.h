#pragma once
#include <Windows.h>

int open_nt_keyedevent_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
