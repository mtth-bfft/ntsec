#pragma once
#include <Windows.h>

int open_nt_job_object(PCTSTR swzNTPath, DWORD dwRightsRequired, HANDLE *phOut);
