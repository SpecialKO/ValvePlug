// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS      ((NTSTATUS)0x00000000L)

#include "xinput_defs.h"
#include "SKinHook/MinHook.h"

#include <Shlwapi.h>
#include <atlbase.h>

using CreateFile2_pfn =
  HANDLE (WINAPI *)(LPCWSTR,DWORD,DWORD,DWORD,
                      LPCREATEFILE2_EXTENDED_PARAMETERS);

using CreateFileW_pfn =
  HANDLE (WINAPI *)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,
                      DWORD,DWORD,HANDLE);

using CreateFileA_pfn =
  HANDLE (WINAPI *)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,
                      DWORD,DWORD,HANDLE);

#endif //PCH_H
