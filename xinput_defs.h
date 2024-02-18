#pragma once
#include <windef.h>

typedef struct _XINPUT_GAMEPAD {
  WORD  wButtons;
  BYTE  bLeftTrigger;
  BYTE  bRightTrigger;
  SHORT sThumbLX;
  SHORT sThumbLY;
  SHORT sThumbRX;
  SHORT sThumbRY;
} XINPUT_GAMEPAD, *PXINPUT_GAMEPAD;

typedef struct _XINPUT_GAMEPAD_EX {
  WORD  wButtons;
  BYTE  bLeftTrigger;
  BYTE  bRightTrigger;
  SHORT sThumbLX;
  SHORT sThumbLY;
  SHORT sThumbRX;
  SHORT sThumbRY;
  DWORD dwUnknown;
} XINPUT_GAMEPAD_EX, *PXINPUT_GAMEPAD_EX;

typedef struct _XINPUT_STATE {
  DWORD          dwPacketNumber;
  XINPUT_GAMEPAD Gamepad;
} XINPUT_STATE, *PXINPUT_STATE;

typedef struct _XINPUT_STATE_EX {
  DWORD             dwPacketNumber;
  XINPUT_GAMEPAD_EX Gamepad;
} XINPUT_STATE_EX, *PXINPUT_STATE_EX;

typedef struct _XINPUT_VIBRATION {
  WORD wLeftMotorSpeed;
  WORD wRightMotorSpeed;
} XINPUT_VIBRATION, *PXINPUT_VIBRATION;

typedef struct _XINPUT_CAPABILITIES {
  BYTE             Type;
  BYTE             SubType;
  WORD             Flags;
  XINPUT_GAMEPAD   Gamepad;
  XINPUT_VIBRATION Vibration;
} XINPUT_CAPABILITIES, *PXINPUT_CAPABILITIES;

typedef struct _XINPUT_BATTERY_INFORMATION {
  BYTE BatteryType;
  BYTE BatteryLevel;
} XINPUT_BATTERY_INFORMATION, *PXINPUT_BATTERY_INFORMATION;

typedef struct _XINPUT_KEYSTROKE {
  WORD  VirtualKey;
  WCHAR Unicode;
  WORD  Flags;
  BYTE  UserIndex;
  BYTE  HidCode;
} XINPUT_KEYSTROKE, *PXINPUT_KEYSTROKE;

typedef struct _XINPUT_CAPABILITIES_EX {
  XINPUT_CAPABILITIES Capabilities;
  WORD                VendorId;
  WORD                ProductId;
  WORD                ProductVersion;
  WORD                unk1;
  DWORD               unk2;
} XINPUT_CAPABILITIES_EX, *PXINPUT_CAPABILITIES_EX;

using XInputGetState_pfn        = DWORD (WINAPI *)(
  _In_  DWORD        dwUserIndex,
  _Out_ XINPUT_STATE *pState
);

using XInputGetStateEx_pfn      = DWORD (WINAPI *)(
  _In_  DWORD            dwUserIndex,
  _Out_ XINPUT_STATE_EX *pState
);

using XInputSetState_pfn        = DWORD (WINAPI *)(
  _In_    DWORD             dwUserIndex,
  _Inout_ XINPUT_VIBRATION *pVibration
);

using XInputGetCapabilities_pfn = DWORD (WINAPI *)(
  _In_  DWORD                dwUserIndex,
  _In_  DWORD                dwFlags,
  _Out_ XINPUT_CAPABILITIES *pCapabilities
);

using XInputGetCapabilitiesEx_pfn = DWORD (WINAPI *)(
  _In_  DWORD dwReserved,
  _In_  DWORD dwUserIndex,
  _In_  DWORD dwFlags,
  _Out_ XINPUT_CAPABILITIES_EX *pCapabilitiesEx
);

using XInputGetBatteryInformation_pfn = DWORD (WINAPI *)(
  _In_  DWORD                       dwUserIndex,
  _In_  BYTE                        devType,
  _Out_ XINPUT_BATTERY_INFORMATION *pBatteryInformation
);

using XInputGetKeystroke_pfn = DWORD (WINAPI *)(
  DWORD             dwUserIndex,
  DWORD             dwReserved,
  PXINPUT_KEYSTROKE pKeystroke
);

using XInputEnable_pfn = void (WINAPI *)(
  _In_ BOOL enable
);

using XInputPowerOff_pfn = DWORD (WINAPI *)(
  _In_ DWORD dwUserIndex
);

#define XINPUT_GETSTATE_ORDINAL           MAKEINTRESOURCEA (002)
#define XINPUT_SETSTATE_ORDINAL           MAKEINTRESOURCEA (003)
#define XINPUT_GETCAPABILITIES_ORDINAL    MAKEINTRESOURCEA (004)
#define XINPUT_ENABLE_ORDINAL             MAKEINTRESOURCEA (005)
#define XINPUT_GETSTATEEX_ORDINAL         MAKEINTRESOURCEA (100)
#define XINPUT_POWEROFF_ORDINAL           MAKEINTRESOURCEA (103)
#define XINPUT_GETCAPABILITIES_EX_ORDINAL MAKEINTRESOURCEA (108)

