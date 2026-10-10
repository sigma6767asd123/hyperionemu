#pragma once

#include <cstdint>

#include "emulator/offsets.h"

namespace emu {

inline constexpr bool kRandHwid = true; // turn this off if u dont want hwid seed randomization
inline constexpr bool kRandId = true; // turn this off if u dont want client identity randomization
inline constexpr bool kCloseInsteadOfTray = true; // disable the system tray and close roblox normally
inline constexpr bool kLoadMod = true; // toggle this if u want it to load a module on startup, configure it below
inline constexpr wchar_t kModDll[] = L"module.dll"; // modify this if u want to load another dll

inline constexpr std::uint32_t kImageSize = 0x09127000u;
inline constexpr std::uint32_t kTextRva = 0x00001000u;
inline constexpr std::uint32_t kTextSize = 0x06180E00u;
inline constexpr std::uint32_t kTextMap = 0x06180000u;
inline constexpr std::uint32_t kTextPad = 0x00001000u;
inline constexpr std::uint32_t kRtOff = kTextSize;
inline constexpr std::uint32_t kRtSize = off::kRtCount * 12u;
inline constexpr std::uint32_t kPayloadSize = kTextSize + 8u + kRtSize;

}
