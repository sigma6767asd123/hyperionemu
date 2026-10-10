made by oracle for `version-cec3ad5889b447cf`

## layout

- `emulator/` the emulator source
- `deps/7zip/` 7zip build
- `deps/lzma/` the compressor
- `build/` this is where the emulator will output when u build it

## build

open `emulator.sln`, select `Release (please x64)` and build the solution.

the output is build into `build/RobloxPlayerBeta.dll`.

## install

copy `RobloxPlayerBeta.dll` and your `module.dll` (optional) into the roblox folder, then launch roblox.

## configuration

all settings are in `emulator/include/config/config.h`.

- `kRandHwid = true` randomizes the smbios uuid and adapter addresses seen by the client; set it to `false` to keep the real values
- `kRandId = true` randomizes the browser tracker, protocol/cookie/app-storage btid and postlogin telemetry values; set it to `false` to keep the originals
- `kCloseInsteadOfTray = true` disables the system tray so closing roblox shuts it down normally
- `kLoadMod = true` loads the configured module on startup; set it to `false` to disable startup module loading
- `kModDll = L"module.dll"` selects the module filename
