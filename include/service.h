#pragma once
#include <Windows.h>
#include "include\targets.h"

int enumerate_services_with(DWORD dwDesiredAccess);
int open_service(PCTSTR swzName, target_t *pTargetType, DWORD dwRightsRequired, SC_HANDLE *phOut);
