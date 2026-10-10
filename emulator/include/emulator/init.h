#pragma once

#include "emulator/state.h"

namespace emu {

bool init();
bool prep();
bool ep();

extern "C" DWORD WINAPI entry();

}
