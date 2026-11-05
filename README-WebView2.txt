ipscan - IE/ActiveX + WebView2 portable viewer
=============================================

Run ipscan.exe (32-bit recommended) or ipscan-x64.exe directly.
No application installation is required. Keep both executables together
if you use the 64-bit scanner: camera windows still launch the 32-bit EXE.

Windows 10/11 with Microsoft Edge WebView2 Evergreen Runtime is required
for modern websites. If it is unavailable, the IE/ActiveX viewer continues
to work. The WebView2 SDK loader is embedded in both executables, so no
DLL needs to be distributed separately.

- Known IP cameras and NVRs default to IE for legacy ActiveX compatibility.
- Other devices default to WebView2. Blank legacy pages can switch in place.
- The Edge button switches between IE and WebView2. Pale blue means Edge is active.
- If WebView2 Runtime is missing, the viewer offers Microsoft's download page.
  We do not bundle the online installer: it would become outdated and would
  need internet access anyway. The Windows browser runtime is installed once.
- Navigation controls, address entry, resizing, form autofill, and popup
  redirection work in WebView2. Credentials are only injected on the
  original device host (never on an unrelated redirect).
- WebView2 browser data lives in %LOCALAPPDATA%\ipscan-webview2.
- The viewer logs to ipscan-viewer.log beside the EXE if writable.
- Camera OSD text discovery uses authenticated ONVIF GetOSDs even when the
  device model was already recognized. Configure a Cameras login profile
  with ONVIF-capable credentials; some cameras do not expose OSD via ONVIF.

Source build:
  Install Zig 0.13 and run ./build.sh from a suitable Unix shell.
  The SDK headers and embedded loader resources are under vendor/webview2.
  The .lib static loader archives are not needed.

This release was cross-compiled for both architectures. Actual camera,
ActiveX, WebView2 and solar-inverter behavior needs testing on Windows.
