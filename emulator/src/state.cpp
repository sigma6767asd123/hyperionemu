#include "emulator/common.h"

namespace emu {

HMODULE g_Self = nullptr;
unsigned char *g_Base = nullptr;
std::wstring g_Dir;
PVOID g_Veh = nullptr;
BCRYPT_ALG_HANDLE g_Hash = nullptr;
ULONG g_HashObj = 0;
LARGE_INTEGER g_T0{};
LARGE_INTEGER g_T1{};
std::uint32_t g_Seed = 0;
FirmwareFn g_Firmware = nullptr;
AdaptersFn g_Adapters = nullptr;

}
