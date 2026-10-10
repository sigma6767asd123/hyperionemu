#include "emulator/common.h"

#include <algorithm>
#include <cstring>

namespace emu {
namespace {

void
smbios(unsigned char *Buf, std::size_t Len)
{
    std::uint32_t tableLen = 0;
    unsigned char *p;
    unsigned char *end;

    if (!Buf || Len < 8) {
        return;
    }
    std::memcpy(&tableLen, Buf + 4, sizeof(tableLen));
    p = Buf + 8;
    end = p + std::min<std::size_t>(tableLen, Len - 8);
    while (p + 4 <= end) {
        const std::size_t elen = p[1];
        unsigned char *scan;
        std::size_t i;
        std::uint32_t state;

        if (elen < 4 || p + elen > end) {
            break;
        }
        if (p[0] == 1 && elen >= 24) {
            state = g_Seed ^ 0xa511e9b3u;
            for (i = 0; i < 16; ++i) {
                if ((i & 3u) == 0) {
                    xors(state);
                }
                p[8 + i] = static_cast<unsigned char>(state >> ((i & 3u) * 8u));
            }
            p[14] = static_cast<unsigned char>((p[14] & 0x0fu) | 0x40u);
            p[16] = static_cast<unsigned char>((p[16] & 0x3fu) | 0x80u);
        }
        scan = p + elen;
        while (scan + 1 < end && (scan[0] != 0 || scan[1] != 0)) {
            ++scan;
        }
        if (scan + 1 >= end) {
            break;
        }
        p = scan + 2;
    }
}

}

bool
seed()
{
    if constexpr (!kRandHwid && !kRandId) {
        return true;
    }
    return BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&g_Seed), sizeof(g_Seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0 && g_Seed != 0;
}

UINT WINAPI
firmware(DWORD Provider, DWORD Id, PVOID Buf, DWORD Len)
{
    UINT got;

    if (!g_Firmware) {
        return 0;
    }
    got = g_Firmware(Provider, Id, Buf, Len);
    if (kRandHwid && Provider == 0x52534d42u && Buf && got && got <= Len) {
        smbios(static_cast<unsigned char *>(Buf), got);
    }
    return got;
}

ULONG WINAPI
adapters(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES Buf, PULONG Size)
{
    const ULONG cap = Size ? *Size : 0;
    const ULONG st = g_Adapters ? g_Adapters(Family, Flags, Reserved, Buf, Size) : ERROR_INVALID_FUNCTION;
    std::uintptr_t lo;
    std::uintptr_t hi;
    PIP_ADAPTER_ADDRESSES cur;
    std::uint32_t i;

    if (!kRandHwid || st != NO_ERROR || !Buf || !Size || cap == 0) {
        return st;
    }
    lo = reinterpret_cast<std::uintptr_t>(Buf);
    hi = lo + cap;
    if (hi < lo) {
        return st;
    }
    cur = Buf;
    for (i = 0; cur && i < 256; ++i) {
        const auto at = reinterpret_cast<std::uintptr_t>(cur);
        ULONG n;
        std::uint32_t state;
        ULONG j;

        if (at < lo || at > hi || hi - at < sizeof(IP_ADAPTER_ADDRESSES)) {
            break;
        }
        n = std::min<ULONG>(cur->PhysicalAddressLength, MAX_ADAPTER_ADDRESS_LENGTH);
        state = g_Seed ^ cur->IfIndex ^ (cur->Ipv6IfIndex << 16) ^ (0x9e3779b9u * (i + 1u));
        for (j = 0; j < n; ++j) {
            if ((j & 3u) == 0) {
                xors(state);
            }
            cur->PhysicalAddress[j] = static_cast<unsigned char>(state >> ((j & 3u) * 8u));
        }
        if (n) {
            cur->PhysicalAddress[0] = static_cast<unsigned char>((cur->PhysicalAddress[0] | 2u) & 0xfeu);
        }
        cur = cur->Next;
    }
    return st;
}

}
