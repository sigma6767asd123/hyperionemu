#pragma once

#include "emulator/state.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace emu {

std::wstring path(const std::wstring &Dir, const wchar_t *Name);
bool wr(void *Dst, const void *Src, std::size_t Size, DWORD Prot);
bool cfg(void *Ptr);
void jmpAbs(unsigned char Out[12], const void *Target);
bool jmpRel(void *From, const void *To, DWORD Prot);
std::uint32_t xors(std::uint32_t &State);

}
