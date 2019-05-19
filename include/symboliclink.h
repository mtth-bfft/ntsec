#pragma once
#include <Windows.h>

int open_nt_symbolic_link_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
