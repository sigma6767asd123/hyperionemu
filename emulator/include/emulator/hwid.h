#pragma once

#include "emulator/state.h"

namespace emu {

bool seed();
UINT WINAPI firmware(DWORD Provider, DWORD Id, PVOID Buf, DWORD Len);
ULONG WINAPI adapters(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES Buf, PULONG Size);

}
