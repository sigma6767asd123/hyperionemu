#include "emulator/common.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <string_view>

namespace emu {
namespace {

struct HookSlot {
    unsigned char *At;
    unsigned char Old[16];
    unsigned char Neu[16];
};

struct Sv {
    const char *Ptr;
    std::size_t Len;
};

using IdFn = std::uintptr_t (*)(void *, const Sv *, const Sv *, unsigned char);

HookSlot g_IdHook{};
IdFn g_IdOrig = nullptr;
void *g_IdTramp = nullptr;

constexpr unsigned char kIdSig[17] = {0x48, 0x89, 0x5c, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8d, 0x6c, 0x24, 0xc9};

void
jmpA(unsigned char Out[16], const void *Target)
{
    Out[0] = 0xff;
    Out[1] = 0x25;
    std::memset(Out + 2, 0, 4);
    std::memcpy(Out + 6, &Target, sizeof(Target));
}

bool
cas(unsigned char *At, const unsigned char Expect[16], const unsigned char Desire[16])
{
    alignas(16) long long cmp[2]{};
    long long lo = 0;
    long long hi = 0;
    DWORD old = 0;
    DWORD tmp = 0;
    bool ok;

    if ((reinterpret_cast<std::uintptr_t>(At) & 15) != 0) {
        return false;
    }
    if (!VirtualProtect(At, 16, PAGE_EXECUTE_READWRITE, &old)) {
        return false;
    }
    std::memcpy(cmp, Expect, 16);
    std::memcpy(&lo, Desire, 8);
    std::memcpy(&hi, Desire + 8, 8);
    ok = _InterlockedCompareExchange128(reinterpret_cast<volatile long long *>(At), hi, lo, cmp) != 0;
    FlushInstructionCache(GetCurrentProcess(), At, 16);
    VirtualProtect(At, 16, old, &tmp);
    return ok;
}

bool
hookA(HookSlot &Slot, unsigned char *At, const unsigned char Sig[16], const void *Detour)
{
    if (std::memcmp(At, Sig, 16) != 0) {
        return false;
    }
    Slot.At = At;
    std::memcpy(Slot.Old, At, 16);
    std::memcpy(Slot.Neu, At, 16);
    jmpA(Slot.Neu, Detour);
    if (cas(Slot.At, Slot.Old, Slot.Neu)) {
        return true;
    }
    Slot.At = nullptr;
    return false;
}

void
hookD(HookSlot &Slot)
{
    if (!Slot.At) {
        return;
    }
    cas(Slot.At, Slot.Neu, Slot.Old);
    Slot.At = nullptr;
}

template <typename Fn>
void
trampF(void *&Mem, Fn &Out)
{
    Out = nullptr;
    if (Mem) {
        VirtualFree(Mem, 0, MEM_RELEASE);
        Mem = nullptr;
    }
}

bool
trampX(void *Mem, std::size_t Size)
{
    DWORD old = 0;

    if (!VirtualProtect(Mem, Size, PAGE_EXECUTE_READ, &old)) {
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), Mem, Size);
    return true;
}

bool
idT(unsigned char *At)
{
    unsigned char code[31]{};
    std::uintptr_t resume;

    std::memcpy(code, At, sizeof(kIdSig));
    code[17] = 0xff;
    code[18] = 0x25;
    resume = reinterpret_cast<std::uintptr_t>(At + sizeof(kIdSig));
    std::memcpy(code + 23, &resume, sizeof(resume));
    g_IdTramp = VirtualAlloc(nullptr, sizeof(code), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!g_IdTramp) {
        return false;
    }
    std::memcpy(g_IdTramp, code, sizeof(code));
    if (!trampX(g_IdTramp, sizeof(code))) {
        trampF(g_IdTramp, g_IdOrig);
        return false;
    }
    g_IdOrig = reinterpret_cast<IdFn>(g_IdTramp);
    return true;
}

bool
svEq(const Sv *S, std::string_view V)
{
    return S && S->Ptr && S->Len == V.size() && std::memcmp(S->Ptr, V.data(), V.size()) == 0;
}

unsigned int
idKind(const Sv *Key)
{
    if (!Key || !Key->Ptr || !Key->Len) {
        return 0;
    }
    switch (Key->Len) {
    case 15:
        if (svEq(Key, "PostLoginUserID")) {
            return 2;
        }
        break;
    case 10:
        if (svEq(Key, "cookieBTID") || svEq(Key, "CookieBTID")) {
            return 1;
        }
        break;
    case 14:
        if (svEq(Key, "AppStorageBTID")) {
            return 1;
        }
        break;
    case 16:
        if (svEq(Key, "browserTrackerId")) {
            return 1;
        }
        break;
    case 17:
        if (svEq(Key, "protocolStringBTID")) {
            return 1;
        }
        break;
    default:
        break;
    }
    return 0;
}

std::uintptr_t
id(void *Obj, const Sv *Key, const Sv *Val, unsigned char Flags)
{
    const unsigned int kind = kRandId ? idKind(Key) : 0;
    char buf[512]{};
    std::uint32_t state;
    std::size_t i;
    Sv spoof;

    if (!g_IdOrig || !kind || !Val || !Val->Ptr || !Val->Len || Val->Len > 512) {
        return g_IdOrig ? g_IdOrig(Obj, Key, Val, Flags) : 0;
    }
    state = g_Seed ^ (kind == 1 ? 0x6c8e9cf5u : 0xa37f41d9u) ^ static_cast<std::uint32_t>(Val->Len * 0x9e3779b9u);
    for (i = 0; i < Val->Len; ++i) {
        const unsigned char c = static_cast<unsigned char>(Val->Ptr[i]);
        std::uint32_t r;

        state ^= static_cast<std::uint32_t>(c) + static_cast<std::uint32_t>(i * 0x45d9f3bu);
        r = xors(state);
        if (c >= '0' && c <= '9') {
            buf[i] = static_cast<char>('0' + r % 10u);
        } else if (c >= 'a' && c <= 'f') {
            buf[i] = static_cast<char>('a' + r % 6u);
        } else if (c >= 'A' && c <= 'F') {
            buf[i] = static_cast<char>('A' + r % 6u);
        } else if (c >= 'a' && c <= 'z') {
            buf[i] = static_cast<char>('a' + r % 26u);
        } else if (c >= 'A' && c <= 'Z') {
            buf[i] = static_cast<char>('A' + r % 26u);
        } else {
            buf[i] = static_cast<char>(c);
        }
    }
    if (Val->Ptr[0] >= '1' && Val->Ptr[0] <= '9' && buf[0] == '0') {
        buf[0] = static_cast<char>('1' + xors(state) % 9u);
    }
    spoof = {buf, Val->Len};
    return g_IdOrig(Obj, Key, &spoof, Flags);
}

}

bool
hookIN()
{
    auto *ip = g_Base + off::kIdJson;

    if constexpr (kRandId) {
        if (std::memcmp(ip, kIdSig, 16) != 0) {
            return false;
        }
        if (!idT(ip) || !hookA(g_IdHook, ip, kIdSig, reinterpret_cast<const void *>(&id))) {
            trampF(g_IdTramp, g_IdOrig);
            return false;
        }
    }
    return true;
}

void
hookOUT()
{
    hookD(g_IdHook);
    trampF(g_IdTramp, g_IdOrig);
}

}
