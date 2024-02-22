# What is Valve Plug?

Valve Plug is a drop-in patch to the Steam client to deny it access to input devices using the XInput API and any API that opens handles to HID devices.

The scope of APIs indirectly disabled _(because they use HID device I/O)_ extends to portions of:
 * SetupAPI
 * DirectInput
 * RawInput
 * WinMM


### Why Was it Created?

To be blunt, Steam is pathologically unable to accept NO for an answer.

Just as the Steam overlay injects its payload into games launched through the Steam client (or that initialize `steam_api{64}.dll`) and hooks input APIs regardless what settings an end-user selects, Steam Input has various device enumeration and initialization code in the Steam client that cannot be turned off.

### Why is Undefeatable Input Device Manipulation a Problem?

Recall that HID device files have broad scope encompassing APIs that software never directly touches and whose developers may know nothing about. ***Writing*** HID device state, as Steam Input does during initialization, has permanent side-effects that affect all software on Windows trying to share access to said input devices.

<br>

# A case study in breaking software you did not write

The most pressing concern with Steam Input's current (2024) implementation are side-effects of its device initialization on Bluetooth PlayStation controllers.

On DualShock 4 and DualSense controllers, when initially paired over Bluetooth, they use a simplified input reporting protocol with roughly the capabilities of a DualShock 3 controller and the same button layout. That compatibility mode disengages as soon as any device state (i.e. haptics, LEDs, powersaving mode) is written.

Writing the more advanced device state over Bluetooth is not something software can do accidentally. It requires a special checksum, the details of which are known to software like Special K, Steam Input, DualSenseX, DS4Windows and various emulators that are written specifically for DualShock 4 / DualSense.

### The effects of DualShock 4 / DualSense Enhanced Software over Bluetooth
As soon as any software successfully handshakes advanced device state over Bluetooth, the controller ***persistently*** changes into a different mode with a different set of buttons, analog axes and HID features. This pulls the rug out from underneath DirectInput drivers, that only understand the communication protocol the controller was in when it first paired with the PC.

Games using DirectInput, or an API layered on top of it (such as WinMM Joystick) will still see the Bluetooth HID device and can still poll it, but DirectInput no longer understands the device and input becomes nonsense. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Often games will start spinning in circles and rapidly activating random menus; ***unplayable!***

### What makes Steam Input different?

DS4Windows, DualSenseX, Special K, (random emulator), ... all have to be requested by the user before they will touch your devices. Off is off, launching a game you bought on PC 20 years ago does not necessarily start any of that software.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;***Steam, on the other hand, is requisite DRM for many games!***

Steam is going to start up constantly unless you actively avoid buying games from Valve.

Having to exit the Steam client and power-cycle your PlayStation controller because Steam Input changed the internal working state of your device is ridiculous, especially when you understand that the various "Off" settings in Steam Input do nothing to change any of this behavior.
<br><br>
> _Any Steam Input native game can initialize the SteamInput API and  permanently break your PlayStation controller until you power-cycle it. &nbsp;&nbsp;&nbsp;&nbsp;**Regardless what settings you select in the Steam client (!!!)**_

<br>
<hr>
<h1>
&nbsp;&nbsp;Steam sees controller — Steam touches controller</h1>

### &nbsp;&nbsp;&nbsp;&nbsp;Consent? Never heard of it.

Options labeled "Off" that give the end-user the illusion of control, while doing nothing, are something of an unappreciated running joke with Valve.

Thus, you can cram this DLL in Steam's plug hole and now it has a proper "Off" setting.

<br>
<hr>
<br>

# Installation and Configuration
### To install, simply drop `XInput1_4.dll` into your Steam client's install directory.

The necessary code patches to block Steam from using XInput or HID are applied by default, and remain active until the Steam client is restarted. The DLL will be locked while the client is running, so to completely remove this the client must be exited.

Steam Input can be programatically enabled or disabled by manually creating the following registry key:

> HKCU\Software\Kaldaien\ValvePlug\FillTheSwamp

This is a (32-bit DWORD):

 * 0x0 = Steam Input is Allowed
 * 0x1 = Steam Input is Disallowed&nbsp;&nbsp;&nbsp;&nbsp;**(Default)**
