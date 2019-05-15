#pragma once
#include <Windows.h>

int enumerate_files_with(PCTSTR swzBaseNTPath, DWORD dwDesiredAccess);
int enumerate_namedpipes_with(DWORD dwDesiredAccess);
