#pragma once
#include <Windows.h>

int open_nt_section_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
