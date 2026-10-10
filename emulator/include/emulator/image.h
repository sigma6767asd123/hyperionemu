#pragma once

#include "emulator/state.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace emu {

bool img();
bool payload(std::vector<unsigned char> &Out);
bool restore(const unsigned char *Payload, std::size_t Size);
bool sec();
bool imp();
bool token(std::uint64_t &Out);
bool proxy();
bool png();
bool lua();
bool tray();

}
