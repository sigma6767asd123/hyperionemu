#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <iphlpapi.h>

#include <cstdint>
#include <string>

namespace emu {

using FirmwareFn = UINT(WINAPI *)(DWORD, DWORD, PVOID, DWORD);
using AdaptersFn = ULONG(WINAPI *)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);

extern HMODULE g_Self;
extern unsigned char *g_Base;
extern std::wstring g_Dir;
extern PVOID g_Veh;
extern BCRYPT_ALG_HANDLE g_Hash;
extern ULONG g_HashObj;
extern LARGE_INTEGER g_T0;
extern LARGE_INTEGER g_T1;
extern std::uint32_t g_Seed;
extern FirmwareFn g_Firmware;
extern AdaptersFn g_Adapters;

}
