#include "emulator/common.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace emu {
namespace {

constexpr unsigned char kCs[0x80] = {
    0xB4, 0x48, 0xDF, 0x04, 0xE7, 0x0F, 0x2A, 0xB9, 0xFA, 0xF3, 0x98, 0xB6, 0x68, 0x51, 0xCC, 0x14, 0x3B, 0x61, 0x60, 0xF5, 0x7D, 0x4F, 0xDC, 0x31, 0xDC, 0x47,
    0xBB, 0x16, 0xD1, 0xB0, 0x01, 0xD4, 0xCE, 0x9B, 0x19, 0xD0, 0x1A, 0x9E, 0x2B, 0x39, 0x64, 0xBC, 0x5B, 0x81, 0xD7, 0xA5, 0xC9, 0xDD, 0xD4, 0x49, 0x88, 0x2C,
    0xE7, 0x54, 0x3F, 0x7E, 0xEC, 0x8D, 0x02, 0x36, 0x1A, 0xF5, 0x6B, 0xCD, 0x0A, 0xAE, 0xEC, 0xE0, 0x94, 0x80, 0x66, 0x10, 0xD4, 0x51, 0x4B, 0x98, 0xF1, 0xDE,
    0xB0, 0xB5, 0x0A, 0x38, 0x19, 0x6D, 0xA8, 0x67, 0x1A, 0xD8, 0x51, 0x06, 0x41, 0xFA, 0xC0, 0x4F, 0xAB, 0xF6, 0x27, 0xAA, 0x62, 0xF0, 0xE3, 0x85, 0x50, 0xA6,
    0xA9, 0x48, 0xF0, 0x43, 0xE5, 0xA2, 0x68, 0x32, 0xDE, 0x30, 0x88, 0x48, 0x23, 0xC4, 0xAB, 0x60, 0x81, 0xDC, 0x1F, 0x81, 0xE8, 0xC5, 0x10, 0xC5,
};
constexpr unsigned char kFaultProlog[7] = {0xEB, 0x05, 0xB8, 0x01, 0x00, 0x00, 0x00};

enum class SvcKind : std::uint8_t {
    None,
    Timing,
    Banner,
    Challenge,
    Callbacks,
    Records,
};

struct SvcRule {
    std::uintptr_t Fault;
    std::uint64_t Ret;
    std::uint64_t Rcx;
    bool MatchRcx;
    SvcKind Kind;
    std::uint64_t OkRax;
};

constexpr SvcRule kSvc[] = {
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-10)), 0x04E2D066u, 0, false, SvcKind::None, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-12)), 0x04E2D094u, 0, false, SvcKind::Timing, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-9)), 0x04E2D0B4u, 0, false, SvcKind::Banner, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-11)), 0x04E2D0E8u, 1, true, SvcKind::Challenge, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-11)), 0x04E2D124u, 3, true, SvcKind::None, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-5)), 0x0358B15Cu, 0, false, SvcKind::None, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-8)), 0x0358B187u, 0, false, SvcKind::None, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-7)), 0x00A1CF4Au, 0, false, SvcKind::Callbacks, 0xD3A84AB4u},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-7)), 0x00A20E0Au, 0, false, SvcKind::Callbacks, 0xD3A84AB4u},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-7)), 0x00F1476Au, 0, false, SvcKind::Callbacks, 0xD3A84AB4u},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-7)), 0x0297AA2Au, 0, false, SvcKind::Callbacks, 0xD3A84AB4u},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-7)), 0x04C7158Au, 0, false, SvcKind::Callbacks, 0xD3A84AB4u},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-3)), 0x0297CFF1u, 0, false, SvcKind::Callbacks, 0xD3A84AB4u},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-3)), 0x02980C21u, 0, false, SvcKind::None, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-11)), 0x04E2D794u, 4, true, SvcKind::None, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-4)), 0x04E2D7B1u, 0, false, SvcKind::None, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-11)), 0x04E2E0BFu, 5, true, SvcKind::Records, 0},
    {static_cast<std::uintptr_t>(static_cast<std::int64_t>(-11)), 0x04E2E10Fu, 5, true, SvcKind::Records, 0},
};

bool
hash(const unsigned char *In, ULONG Len, unsigned char Out[32])
{
    alignas(16) unsigned char obj[1024]{};
    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS st;

    if (!g_Hash || g_HashObj == 0 || g_HashObj > 1024) {
        return false;
    }
    st = BCryptCreateHash(g_Hash, &hash, obj, g_HashObj, nullptr, 0, 0);
    if (st >= 0) {
        st = BCryptHashData(hash, const_cast<PUCHAR>(In), Len, 0);
    }
    if (st >= 0) {
        st = BCryptFinishHash(hash, Out, 32, 0);
    }
    if (hash) {
        BCryptDestroyHash(hash);
    }
    return st >= 0;
}

bool
challenge(CONTEXT *Cx)
{
    std::uint32_t cap;
    std::uint32_t *len;
    std::uint64_t rnd{};
    std::uint64_t nonce;
    std::uint64_t tag;
    std::uint32_t key;
    std::uint32_t chk;
    unsigned char kb[4];
    unsigned char buf[0xC0]{};
    std::size_t b;
    std::size_t i;

    if (!Cx || !Cx->R9) {
        return false;
    }
    cap = *reinterpret_cast<const std::uint32_t *>(Cx->Rsp + 0x28);
    len = *reinterpret_cast<std::uint32_t **>(Cx->Rsp + 0x30);
    if (!len || cap < 0xC0) {
        return false;
    }
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&rnd), sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return false;
    }
    nonce = rnd ? rnd : 1;
    tag = 0x00000C3823000000ull | (GetTickCount64() & 0x0000000000FFFFFFull);
    key = static_cast<std::uint32_t>(nonce);
    kb[0] = static_cast<unsigned char>(key);
    kb[1] = static_cast<unsigned char>(key >> 8);
    kb[2] = static_cast<unsigned char>(key >> 16);
    kb[3] = static_cast<unsigned char>(key >> 24);
    std::memcpy(buf + 0x20, &nonce, sizeof(nonce));
    {
        const std::uint64_t et = nonce ^ tag;
        std::memcpy(buf + 0x28, &et, sizeof(et));
    }
    chk = key ^ 1u;
    std::memcpy(buf + 0x30, &chk, sizeof(chk));
    std::memcpy(buf + 0x34, &key, sizeof(key));
    for (b = 0; b < 4; ++b) {
        for (i = 0; i < 0x20; ++i) {
            buf[0x40 + b * 0x20 + i] = kCs[b * 0x20 + i] ^ kb[b];
        }
    }
    if (!hash(buf + 0x20, 0xA0, buf)) {
        return false;
    }
    std::memcpy(reinterpret_cast<void *>(Cx->R9), buf, sizeof(buf));
    *len = sizeof(buf);
    return true;
}

void
timing(CONTEXT *Cx)
{
    std::uint64_t ds[8]{};
    FILETIME ft{};
    LARGE_INTEGER now{};
    std::uint64_t first;
    std::uint64_t mid;
    std::uint64_t last;
    std::uint64_t span;

    if (!Cx || !Cx->Rcx) {
        return;
    }
    GetSystemTimeAsFileTime(&ft);
    ds[0] = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    QueryPerformanceCounter(&now);
    first = static_cast<std::uint64_t>(g_T0.QuadPart);
    mid = static_cast<std::uint64_t>(g_T1.QuadPart);
    last = static_cast<std::uint64_t>(now.QuadPart);
    if (!first || first > last) {
        first = last;
    }
    if (!mid || mid < first || mid > last) {
        mid = first + (last - first) * 3 / 4;
    }
    ds[1] = ds[2] = first;
    ds[3] = ds[4] = mid;
    ds[5] = last;
    span = last - first;
    ds[6] = std::max<std::uint64_t>(1, (mid - first) / 10);
    ds[7] = std::max<std::uint64_t>(1, span * 45 / 100);
    std::memcpy(reinterpret_cast<void *>(Cx->Rcx), ds, sizeof(ds));
}

__declspec(noinline) std::uintptr_t
cbA()
{
    return 0;
}

__declspec(noinline) std::uintptr_t
cbB()
{
    return 0;
}

bool
callbacks(CONTEXT *Cx)
{
    unsigned char *dst;
    const std::uint32_t ver = 2;
    const auto a = reinterpret_cast<std::uintptr_t>(&cbA);
    const auto b = reinterpret_cast<std::uintptr_t>(&cbB);

    if (!Cx || !Cx->Rcx || Cx->Rdx < 0x18) {
        return false;
    }
    dst = reinterpret_cast<unsigned char *>(Cx->Rcx);
    std::memcpy(dst, &ver, sizeof(ver));
    std::memcpy(dst + 0x08, &a, sizeof(a));
    std::memcpy(dst + 0x10, &b, sizeof(b));
    return true;
}

bool
banner(CONTEXT *Cx)
{
    static constexpr char kText[] =
        "Copyright (c) Roblox Corporation. Hyperion anti-tamper technology and "
        "the Roblox client are protected under 17 U.S.C. Section 1201. "
        "Development, distribution, or use of circumvention tools constitutes "
        "willful infringement, including violation of terms of use (User Terms, "
        "Section 6.a; see also 17 U.S.C. Section 106).";
    static_assert(sizeof(kText) - 1 == 0x13D);

    if (!Cx || !Cx->Rcx) {
        return false;
    }
    std::memcpy(reinterpret_cast<void *>(Cx->Rcx + 0x20), kText, sizeof(kText) - 1);
    return true;
}

bool
records(CONTEXT *Cx)
{
    std::uint32_t *len;

    if (!Cx || !Cx->Rdx || Cx->R8 != 0x120) {
        return false;
    }
    len = *reinterpret_cast<std::uint32_t **>(Cx->Rsp + 0x30);
    if (!len) {
        return false;
    }
    *len = 0;
    return true;
}

__forceinline bool
svc(CONTEXT *Cx, SvcKind Kind)
{
    switch (Kind) {
    case SvcKind::Timing:
        timing(Cx);
        return true;
    case SvcKind::Banner:
        return banner(Cx);
    case SvcKind::Challenge:
        return challenge(Cx);
    case SvcKind::Callbacks:
        return callbacks(Cx);
    case SvcKind::Records:
        return records(Cx);
    case SvcKind::None:
    default:
        return true;
    }
}

}

LONG CALLBACK
veh(EXCEPTION_POINTERS *Ep)
{
    EXCEPTION_RECORD *rec;
    CONTEXT *cx;
    std::uintptr_t fault;
    std::uint64_t ret;
    std::uint64_t base;
    const unsigned char *site;

    if (!Ep || !Ep->ExceptionRecord || !Ep->ContextRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    rec = Ep->ExceptionRecord;
    if (rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    cx = Ep->ContextRecord;
    fault = reinterpret_cast<std::uintptr_t>(rec->ExceptionAddress);
    if (fault < static_cast<std::uintptr_t>(static_cast<std::int64_t>(-0x1000))) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    ret = *reinterpret_cast<const std::uint64_t *>(cx->Rsp);
    base = reinterpret_cast<std::uint64_t>(g_Base);
    if (ret < base + kTextRva || ret + sizeof(kFaultProlog) > base + kTextRva + kTextMap) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    site = reinterpret_cast<const unsigned char *>(ret);
    if (std::memcmp(site, kFaultProlog, sizeof(kFaultProlog)) != 0) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    ret -= base;
    for (const SvcRule &rule : kSvc) {
        bool ok;

        if (fault != rule.Fault || ret != rule.Ret) {
            continue;
        }
        if (rule.MatchRcx && cx->Rcx != rule.Rcx) {
            continue;
        }
        ok = svc(cx, rule.Kind);
        cx->Rax = ok ? rule.OkRax : 1;
        cx->Rip = *reinterpret_cast<const std::uint64_t *>(cx->Rsp);
        cx->Rsp += sizeof(std::uint64_t);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

}
