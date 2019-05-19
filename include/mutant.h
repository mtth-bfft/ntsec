#pragma once
#include <Windows.h>

int open_nt_mutant_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
