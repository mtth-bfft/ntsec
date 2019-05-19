#pragma once
#include <Windows.h>

int enumerate_services_with(DWORD dwDesiredAccess);
int open_service(PCTSTR swzName, DWORD dwRightsRequired, SC_HANDLE *phOut);
