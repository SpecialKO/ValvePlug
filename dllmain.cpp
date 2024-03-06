
// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "config.h"
#include <cassert>

#pragma comment (lib, "shlwapi.lib")

#ifdef _M_IX86
#pragma comment (lib, "SKinHook/libMinHook.lib")
#else
#pragma comment (lib, "SKinHook/libMinHook64.lib")
#endif

         config_s config;
volatile LONG     __VP_DLL_Refs = 0UL;

static CreateFileA_pfn CreateFileA_Original = nullptr;
static CreateFileW_pfn CreateFileW_Original = nullptr;
static CreateFile2_pfn CreateFile2_Original = nullptr;

static
HANDLE
WINAPI
CreateFileA_Detour (LPCSTR                lpFileName,
                    DWORD                 dwDesiredAccess,
                    DWORD                 dwShareMode,
                    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                    DWORD                 dwCreationDisposition,
                    DWORD                 dwFlagsAndAttributes,
                    HANDLE                hTemplateFile)
{
  if (StrStrIA (lpFileName, R"(\\?\hid)") != nullptr)
  {
    SetLastError (ERROR_NO_SUCH_DEVICE);

    return INVALID_HANDLE_VALUE;
  }

  if (StrStrIA (lpFileName, R"(\\.\pipe)") != nullptr)
  {
    SetLastError (ERROR_NO_SUCH_DEVICE);

    return INVALID_HANDLE_VALUE;
  }

  return
    CreateFileA_Original (
      lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition,
          dwFlagsAndAttributes, hTemplateFile );
}

static
HANDLE
WINAPI
CreateFile2_Detour (
  _In_     LPCWSTR                           lpFileName,
  _In_     DWORD                             dwDesiredAccess,
  _In_     DWORD                             dwShareMode,
  _In_     DWORD                             dwCreationDisposition,
  _In_opt_ LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams )
{
  if (StrStrIW (lpFileName, LR"(\\?\hid)") != nullptr)
  {
    SetLastError (ERROR_NO_SUCH_DEVICE);

    return INVALID_HANDLE_VALUE;
  }

  if (StrStrIW (lpFileName, LR"(\\.\pipe)") != nullptr)
  {
    SetLastError (ERROR_NO_SUCH_DEVICE);

    return INVALID_HANDLE_VALUE;
  }

  return
    CreateFile2_Original (
      lpFileName, dwDesiredAccess, dwShareMode,
        dwCreationDisposition, pCreateExParams );
}

static
HANDLE
WINAPI
CreateFileW_Detour ( LPCWSTR               lpFileName,
                     DWORD                 dwDesiredAccess,
                     DWORD                 dwShareMode,
                     LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                     DWORD                 dwCreationDisposition,
                     DWORD                 dwFlagsAndAttributes,
                     HANDLE                hTemplateFile )
{
  if (StrStrIW (lpFileName, LR"(\\?\hid)") != nullptr)
  {
    SetLastError (ERROR_NO_SUCH_DEVICE);

    return INVALID_HANDLE_VALUE;
  }

  if (StrStrIW (lpFileName, LR"(\\.\pipe)") != nullptr)
  {
    SetLastError (ERROR_NO_SUCH_DEVICE);

    return INVALID_HANDLE_VALUE;
  }

  return
    CreateFileW_Original (
      lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition,
          dwFlagsAndAttributes, hTemplateFile );
}

MH_STATUS
__stdcall
SK_CreateDLLHook2 ( const wchar_t  *pwszModule, const char  *pszProcName,
                          void     *pDetour,          void **ppOriginal,
                          void    **ppFuncAddr )
{
  HMODULE hMod = nullptr;

  // Hook the XInput DLL in System32, not ourself!
  if (StrStrIW (pwszModule, L"XInput1_4") || (! GetModuleHandleExW (GET_MODULE_HANDLE_EX_FLAG_PIN, pwszModule, &hMod)))
  {
    hMod =
      LoadLibraryExW (pwszModule, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32|LOAD_LIBRARY_SAFE_CURRENT_DIRS);

    if (hMod != 0)
      GetModuleHandleExW ( GET_MODULE_HANDLE_EX_FLAG_PIN |
                           GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (wchar_t *)hMod, &hMod );
  }

  void      *pFuncAddr = nullptr;
  MH_STATUS  status    = MH_OK;

  if (hMod == nullptr)
    status = MH_ERROR_MODULE_NOT_FOUND;

  else
  {
    pFuncAddr =
      GetProcAddress (hMod, pszProcName);

    status =
      MH_CreateHook ( pFuncAddr,
                        pDetour,
                          ppOriginal );
  }


  if (status != MH_OK)
  {
    if (status == MH_ERROR_ALREADY_CREATED)
    {
      if (ppOriginal == nullptr)
      {
        SH_Introspect ( pFuncAddr,
                          SH_TRAMPOLINE,
                            ppOriginal );

        return status;
      }

      else if (MH_OK == (status = MH_RemoveHook (pFuncAddr)))
      {
        return SK_CreateDLLHook2 (pwszModule, pszProcName, pDetour, ppOriginal, ppFuncAddr);
      }
    }

    if (ppFuncAddr != nullptr)
       *ppFuncAddr  = nullptr;
  }

  else
  {
    if (ppFuncAddr != nullptr)
       *ppFuncAddr  = pFuncAddr;

    MH_QueueEnableHook (pFuncAddr);
  }

  return status;
}


typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;

using LdrLockLoaderLock_pfn   = NTSTATUS (WINAPI *)(ULONG Flags, ULONG *State, ULONG_PTR *Cookie);
using LdrUnlockLoaderLock_pfn = NTSTATUS (WINAPI *)(ULONG Flags,               ULONG_PTR  Cookie);

extern "C"
NTSTATUS
WINAPI
SK_NtLdr_LockLoaderLock (ULONG Flags, ULONG* State, ULONG_PTR* Cookie)
{
  //// The lock must not be acquired until DllMain (...) returns!
  //if (ReadAcquire (&__VP_DLL_Refs) < 1)
  //  return STATUS_SUCCESS; // No-Op

  static LdrLockLoaderLock_pfn LdrLockLoaderLock =
        (LdrLockLoaderLock_pfn)GetProcAddress (GetModuleHandleW (L"NtDll.dll"),
        "LdrLockLoaderLock");

  if (! LdrLockLoaderLock)
    return ERROR_NOT_FOUND;

  return
    LdrLockLoaderLock (Flags, State, Cookie);
}

extern "C"
NTSTATUS
WINAPI
SK_NtLdr_UnlockLoaderLock (ULONG Flags, ULONG_PTR Cookie)
{
  static LdrUnlockLoaderLock_pfn LdrUnlockLoaderLock =
        (LdrUnlockLoaderLock_pfn)GetProcAddress (GetModuleHandleW (L"NtDll.dll"),
        "LdrUnlockLoaderLock");

  if (! LdrUnlockLoaderLock)
    return ERROR_NOT_FOUND;

  NTSTATUS UnlockLoaderStatus =
    LdrUnlockLoaderLock (Flags, Cookie);

//  // Check for Loader Unlock Failure...
//  if (ReadAcquire (&__VP_DLL_Refs) >= 1 && Cookie != 0)
//  {
//#ifdef DEBUG
//    assert (UnlockLoaderStatus == STATUS_SUCCESS);
//#endif
//  }

  return
    UnlockLoaderStatus;
}

static XInputGetState_pfn          XInputGetState1_4_Original          = nullptr;
static XInputGetStateEx_pfn        XInputGetStateEx1_4_Original        = nullptr;
static XInputGetState_pfn          XInputGetState1_3_Original          = nullptr;
static XInputGetStateEx_pfn        XInputGetStateEx1_3_Original        = nullptr;
static XInputGetState_pfn          XInputGetState9_1_0_Original        = nullptr;
static XInputGetStateEx_pfn        XInputGetStateEx9_1_0_Original      = nullptr;
static XInputGetState_pfn          XInputGetState1_2_Original          = nullptr;
static XInputGetStateEx_pfn        XInputGetStateEx1_2_Original        = nullptr;
static XInputGetState_pfn          XInputGetState1_1_Original          = nullptr;
static XInputGetStateEx_pfn        XInputGetStateEx1_1_Original        = nullptr;
static XInputGetCapabilities_pfn   XInputGetCapabilities1_4_Original   = nullptr;
static XInputGetCapabilitiesEx_pfn XInputGetCapabilitiesEx1_4_Original = nullptr;
static XInputGetCapabilities_pfn   XInputGetCapabilities1_3_Original   = nullptr;
static XInputGetCapabilitiesEx_pfn XInputGetCapabilitiesEx1_3_Original = nullptr;
static XInputGetCapabilities_pfn   XInputGetCapabilities1_2_Original   = nullptr;
static XInputGetCapabilities_pfn   XInputGetCapabilities1_1_Original   = nullptr;
static XInputGetCapabilities_pfn   XInputGetCapabilities9_1_0_Original = nullptr;

//#define FAKE_SUCCESS

DWORD
WINAPI
XInputGetState1_4_Detour (DWORD dwUserIndex, XINPUT_STATE *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetStateEx1_4_Detour (DWORD dwUserIndex, XINPUT_STATE_EX *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetCapabilities1_4_Detour (
  _In_  DWORD                dwUserIndex,
  _In_  DWORD                dwFlags,
  _Out_ XINPUT_CAPABILITIES *pCapabilities )
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetCapabilitiesEx1_4_Detour (
  _In_  DWORD                   dwReserved,
  _In_  DWORD                   dwUserIndex,
  _In_  DWORD                   dwFlags,
  _Out_ XINPUT_CAPABILITIES_EX *pCapabilitiesEx )
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetState1_3_Detour (DWORD dwUserIndex, XINPUT_STATE *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetStateEx1_3_Detour (DWORD dwUserIndex, XINPUT_STATE_EX *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetCapabilities1_3_Detour (
  _In_  DWORD                dwUserIndex,
  _In_  DWORD                dwFlags,
  _Out_ XINPUT_CAPABILITIES *pCapabilities )
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetCapabilitiesEx1_3_Detour (
  _In_  DWORD                   dwReserved,
  _In_  DWORD                   dwUserIndex,
  _In_  DWORD                   dwFlags,
  _Out_ XINPUT_CAPABILITIES_EX *pCapabilitiesEx )
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetState1_2_Detour (DWORD dwUserIndex, XINPUT_STATE *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetStateEx1_2_Detour (DWORD dwUserIndex, XINPUT_STATE_EX *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetCapabilities1_2_Detour (
  _In_  DWORD                dwUserIndex,
  _In_  DWORD                dwFlags,
  _Out_ XINPUT_CAPABILITIES *pCapabilities )
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetState1_1_Detour (DWORD dwUserIndex, XINPUT_STATE *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetStateEx1_1_Detour (DWORD dwUserIndex, XINPUT_STATE_EX *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetCapabilities1_1_Detour (
  _In_  DWORD                dwUserIndex,
  _In_  DWORD                dwFlags,
  _Out_ XINPUT_CAPABILITIES *pCapabilities )
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetState9_1_0_Detour (DWORD dwUserIndex, XINPUT_STATE *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetStateEx9_1_0_Detour (DWORD dwUserIndex, XINPUT_STATE_EX *pState)
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}

DWORD
WINAPI
XInputGetCapabilities9_1_0_Detour (
  _In_  DWORD                dwUserIndex,
  _In_  DWORD                dwFlags,
  _Out_ XINPUT_CAPABILITIES *pCapabilities )
{
#ifndef FAKE_SUCCESS
  return
    ERROR_NOT_CONNECTED;
#else
  return
    ERROR_SUCCESS;
#endif
}


DWORD
WINAPI
ValvePlug_InitThread (LPVOID)
{
  if (MH_OK == MH_Initialize ())
  {
    SK_CreateDLLHook2 ( L"kernel32.dll",
                         "CreateFileW",
                          CreateFileW_Detour,
               (void **)(&CreateFileW_Original), nullptr );

    SK_CreateDLLHook2 ( L"kernel32.dll",
                         "CreateFileA",
                          CreateFileA_Detour,
               (void **)(&CreateFileA_Original), nullptr );

    SK_CreateDLLHook2 ( L"kernel32.dll",
                         "CreateFile2",
                          CreateFile2_Detour,
               (void **)(&CreateFile2_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_4,
                         "XInputGetState",
                          XInputGetState1_4_Detour,
               (void **)(&XInputGetState1_4_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_4,
                          XINPUT_GETSTATEEX_ORDINAL,
                          XInputGetStateEx1_4_Detour,
               (void **)(&XInputGetStateEx1_4_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_4,
                         "XInputGetCapabilities",
                          XInputGetCapabilities1_4_Detour,
               (void **)(&XInputGetCapabilities1_4_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_4,
                          XINPUT_GETCAPABILITIES_EX_ORDINAL,
                          XInputGetCapabilitiesEx1_4_Detour,
               (void **)(&XInputGetCapabilitiesEx1_4_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_3,
                         "XInputGetState",
                          XInputGetState1_3_Detour,
               (void **)(&XInputGetState1_3_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_3,
                          XINPUT_GETSTATEEX_ORDINAL,
                          XInputGetStateEx1_3_Detour,
               (void **)(&XInputGetStateEx1_3_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_3,
                         "XInputGetCapabilities",
                          XInputGetCapabilities1_3_Detour,
               (void **)(&XInputGetCapabilities1_3_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_3,
                          XINPUT_GETCAPABILITIES_EX_ORDINAL,
                          XInputGetCapabilitiesEx1_3_Detour,
               (void **)(&XInputGetCapabilitiesEx1_3_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_2,
                         "XInputGetState",
                          XInputGetState1_2_Detour,
               (void **)(&XInputGetState1_2_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_2,
                          XINPUT_GETSTATEEX_ORDINAL,
                          XInputGetStateEx1_2_Detour,
               (void **)(&XInputGetStateEx1_2_Original), nullptr );
    
    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_2,
                         "XInputGetCapabilities",
                          XInputGetCapabilities1_2_Detour,
               (void **)(&XInputGetCapabilities1_2_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_1,
                         "XInputGetState",
                          XInputGetState1_1_Detour,
               (void **)(&XInputGetState1_1_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_1,
                          XINPUT_GETSTATEEX_ORDINAL,
                          XInputGetStateEx1_1_Detour,
               (void **)(&XInputGetStateEx1_1_Original), nullptr );
    
    SK_CreateDLLHook2 ( config.wszPathToSystemXInput1_1,
                         "XInputGetCapabilities",
                          XInputGetCapabilities1_1_Detour,
               (void **)(&XInputGetCapabilities1_1_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput9_1_0,
                         "XInputGetState",
                          XInputGetState9_1_0_Detour,
               (void **)(&XInputGetState9_1_0_Original), nullptr );

    SK_CreateDLLHook2 ( config.wszPathToSystemXInput9_1_0,
                          XINPUT_GETSTATEEX_ORDINAL,
                          XInputGetStateEx9_1_0_Detour,
               (void **)(&XInputGetStateEx9_1_0_Original), nullptr );
    
    SK_CreateDLLHook2 ( config.wszPathToSystemXInput9_1_0,
                         "XInputGetCapabilities",
                          XInputGetCapabilities9_1_0_Detour,
               (void **)(&XInputGetCapabilities9_1_0_Original), nullptr );

    MH_ApplyQueued ();
  }

  return 0;
}

BOOL
APIENTRY
DllMain ( HMODULE hModule,
          DWORD   ul_reason_for_call,
          LPVOID  lpReserved )
{
  switch (ul_reason_for_call)
  {
    case DLL_PROCESS_ATTACH:
    {
      InterlockedIncrement (&__VP_DLL_Refs);

      config = { };

#ifdef _M_IX86
      GetSystemWow64DirectoryW (config.wszPathToSystemXInput1_4,   MAX_PATH);
      GetSystemWow64DirectoryW (config.wszPathToSystemXInput1_3,   MAX_PATH);
      GetSystemWow64DirectoryW (config.wszPathToSystemXInput1_2,   MAX_PATH);
      GetSystemWow64DirectoryW (config.wszPathToSystemXInput1_1,   MAX_PATH);
      GetSystemWow64DirectoryW (config.wszPathToSystemXInput9_1_0, MAX_PATH);
#else
      GetSystemDirectoryW      (config.wszPathToSystemXInput1_4,   MAX_PATH);
      GetSystemDirectoryW      (config.wszPathToSystemXInput1_3,   MAX_PATH);
      GetSystemDirectoryW      (config.wszPathToSystemXInput1_2,   MAX_PATH);
      GetSystemDirectoryW      (config.wszPathToSystemXInput1_1,   MAX_PATH);
      GetSystemDirectoryW      (config.wszPathToSystemXInput9_1_0, MAX_PATH);
#endif
      PathAppendW              (config.wszPathToSystemXInput1_4,   L"XInput1_4.dll");
      PathAppendW              (config.wszPathToSystemXInput1_3,   L"XInput1_3.dll");
      PathAppendW              (config.wszPathToSystemXInput1_2,   L"XInput1_2.dll");
      PathAppendW              (config.wszPathToSystemXInput1_1,   L"XInput1_1.dll");
      PathAppendW              (config.wszPathToSystemXInput9_1_0, L"XInput9_1_0.dll");

                    CRegKey hkValvePlug;
      if ( ERROR_SUCCESS == hkValvePlug.Open (
             HKEY_CURRENT_USER, LR"(Software\Kaldaien\ValvePlug)" )
         )
      {
        hkValvePlug.QueryDWORDValue (
                 L"FillTheSwamp",
          config.dwFillTheSwamp
        );
      }

      wchar_t                      wszModuleName [MAX_PATH] = { };
      GetModuleFileNameW (hModule, wszModuleName, MAX_PATH);

      if (! StrStrIW (wszModuleName, L"XInput1_4"))
      {
        config.dwFillTheSwamp = false;
      }

      if (config.dwFillTheSwamp != 0x0)
      {
        CloseHandle (
          CreateThread ( nullptr, 0x0, ValvePlug_InitThread,
                         nullptr, 0x0, nullptr )
        );
      }

      DisableThreadLibraryCalls (hModule);
    } break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
      break;

    case DLL_PROCESS_DETACH:
      InterlockedDecrement (&__VP_DLL_Refs);

      if (config.dwFillTheSwamp != 0x0)
      {
        MH_Uninitialize ();
      }
      break;
  }

  return TRUE;
}