#pragma once
#include <Windows.h>

int open_nt_thread_object(PCTSTR swzTarget, DWORD dwRightsRequired, PHANDLE phOut);
int open_nt_thread_by_tid(DWORD dwTID, DWORD dwRightsRequired, PHANDLE phOut);
