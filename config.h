#pragma once

#include <windef.h>

struct config_s {
  wchar_t wszPathToSystemXInput1_4 [MAX_PATH] = L"";
  DWORD   dwFillTheSwamp                      = 0x1;
} static config;

static volatile LONG __VP_DLL_Refs = 0UL;