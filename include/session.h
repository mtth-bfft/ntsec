#pragma once
#include <Windows.h>

int open_nt_session_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
