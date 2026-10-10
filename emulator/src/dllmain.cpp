#include "emulator/common.h"

extern "C" __declspec(dllexport) int
run()
{
    return 1;
}

BOOL WINAPI
DllMain(HINSTANCE Inst, DWORD Reason, LPVOID)
{
    if (Reason == DLL_PROCESS_ATTACH) {
        emu::g_Self = Inst;
        DisableThreadLibraryCalls(Inst);
        emu::g_Base = reinterpret_cast<unsigned char *>(GetModuleHandleW(nullptr));
        if (!emu::g_Base || !emu::img() || !emu::init() || !emu::prep() || !emu::ep()) {
            return FALSE;
        }
        return TRUE;
    }
    if (Reason == DLL_PROCESS_DETACH) {
        emu::hookOUT();
    }
    return TRUE;
}
