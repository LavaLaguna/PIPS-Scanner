PIPS Scanner - portable Windows network scanner and monitor
===========================================================

RUN
  PIPS-Scanner.exe       32-bit (recommended for legacy camera ActiveX)
  PIPS-Scanner-x64.exe   64-bit

No installer is required for PIPS Scanner. The optional embedded Edge viewer
requires Microsoft Edge WebView2 Evergreen Runtime; when it is not installed,
use the viewer's System Browser option or its download link. IE mode remains
available for older cameras and NVRs.

SCANNER AND MONITORING
  Scanner expands to All, NVR/DVR, IP cameras, PCs, RDP and Other.
  Right-click a discovered device and choose Add to Monitoring, then the
  ping interval (5, 10, 30 or 60 seconds). Monitoring groups selected
  devices by subnet with color-coded Alive/Dead totals. Selecting a subnet shows its
  devices, including offline devices. Monitoring runs only while PIPS is open.
  The Monitoring column in both views displays each device's ping interval.
  To apply a context-menu action to multiple devices, select rows using
  Ctrl+click or Shift+click, then right-click one of the selected rows.
  Actions such as opening multiple viewers/connections ask for confirmation.
  Editing a comment for multiple devices assigns the same comment to each.
  Status changes require 3 consecutive failed pings or 2 successful pings
  to avoid alerts from isolated packet loss.
  The bottom status bar shows each of the 4 results of a manual ping as
  colored dots on the left: green=reply, yellow=slow reply,
  red=timeout, gray=pending.

CAMERA LOGIN AND SMB SHARES
  A camera credential profile assigned to a device is available from both
  Scanner and Monitoring. Double-click or the viewer's default Open command
  uses the remembered camera profile where available. Camera HTML/ActiveX
  login automation remains vendor-specific; some forms may resist autofill.
  Explore shares first attempts the current Windows account. If that fails
  due to authentication, PIPS prompts for a different username/password.
  Explore shares also has an explicit "Login with different account" command.
  Windows error 1219 means the system already has a conflicting connection
  to that server; disconnect the existing session before changing users.

DATA AND HISTORY
  By default, the SQLite database is stored at:
      %LOCALAPPDATA%\PIPS Scanner\pips.db
  It contains monitored devices, subnet selections, ping samples, events,
  discovered device metadata and navigation preferences. Ping history is
  retained for 7 days (cleanup takes place while the program runs).
  The database uses SQLite; no separate server or SQLite installation is
  needed. It may have temporary -wal and -shm files while the app runs.

  To keep the SQLite data next to the EXE, create an empty file named
  "portable.flag" beside it BEFORE first launch. The data folder then is
  "Data" beside the EXE, requiring write access to that directory.

MIGRATE TO ANOTHER PC (RECOMMENDED)
  Use the Backup menu in the application to export a .pipsbackup file.
  On the new PC, launch PIPS Scanner and use Backup > Import Backup.
  Enter the same password and confirm replacement of local settings.
  Imported login profiles are re-encrypted for the new Windows user.
  Import creates pips-before-restore.db as a safety copy of the old database.
  A backup replaces the target PC's monitoring lists and settings; it does
  NOT merge them.

SECURITY
  Credential profiles in .pipsbackup files are encrypted using AES-256-GCM
  and a password-derived key (PBKDF2-HMAC-SHA256). The database, device
  names, IPs, ping history and ordinary preferences in that backup ARE NOT
  ENCRYPTED. Protect backups accordingly. In normal operation the existing
  login profiles remain protected by Windows DPAPI and may not be copied
  directly to another user's/machine's profile without export/import.

NOTES
  Cameras that do not expose OSD names in their first scan receive delayed
  ONVIF retries after the initial scan. OSD retrieval depends on device
  support and valid authentication; not every camera offers the field.
  This build has been cross-compiled for Windows x86/x64. Verify operation
  on the target Windows machines and with actual devices before deployment.

BUILDING
  Run build.sh with a recent Zig C compiler (x86 and x64 Windows GNU targets).
  SQLite source is included under vendor/sqlite.

Support Email: webmastersharp94@gmail.com
