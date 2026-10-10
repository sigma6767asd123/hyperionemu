#include "emulator/common.h"

#include <cstdint>
#include <cstring>
#include <cwchar>
#include <intrin.h>
#include <vector>

namespace emu {
namespace {

using TlsFn = void(NTAPI *)(void *, DWORD, void *);
using EpFn = DWORD(WINAPI *)();

bool
epA(const void *Fn)
{
    unsigned char jmp[12]{};

    jmpAbs(jmp, Fn);
    return wr(g_Base + off::kEpOrig, jmp, sizeof(jmp), PAGE_EXECUTE_READ) && cfg(g_Base + off::kEpOrig);
}

bool
stack(void *Old, void *Neu)
{
    const auto a = reinterpret_cast<std::uintptr_t>(Old);
    const auto b = reinterpret_cast<std::uintptr_t>(Neu);
    auto cur = reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress());
    const auto top = __readgsqword(0x08);
    unsigned int hits = 0;

    cur = (cur + sizeof(std::uintptr_t) - 1u) & ~(sizeof(std::uintptr_t) - 1u);
    if (!a || !b || !top || cur >= top || top - cur > 0x1000000u) {
        return false;
    }
    for (auto *p = reinterpret_cast<std::uintptr_t *>(cur); p < reinterpret_cast<std::uintptr_t *>(top); ++p) {
        if (*p != a) {
            continue;
        }
        *p = b;
        ++hits;
    }
    _mm_mfence();
    return hits != 0;
}

DWORD WINAPI
lod(void *)
{
    static wchar_t buf[MAX_PATH]{};
    const auto full = path(g_Dir, kModDll);

    if (full.empty() || full.size() >= MAX_PATH) {
        return 0;
    }
    std::memcpy(buf, full.c_str(), (full.size() + 1u) * sizeof(wchar_t));
    Sleep(5000);
    LoadLibraryW(buf);
    return 0;
}

}

bool
init()
{
    wchar_t dir[MAX_PATH]{};
    DWORD n;
    wchar_t *slash;
    std::vector<unsigned char> buf;
    NTSTATUS st;
    ULONG got = 0;
    std::uint64_t tok = 0;

    n = GetModuleFileNameW(g_Self, dir, MAX_PATH);
    if (!n || n >= MAX_PATH) {
        return false;
    }
    slash = wcsrchr(dir, L'\\');
    if (slash) {
        *slash = L'\0';
    }
    g_Dir.assign(dir);
    g_Base = reinterpret_cast<unsigned char *>(GetModuleHandleW(nullptr));
    QueryPerformanceCounter(&g_T0);
    if (!img()) {
        return false;
    }
    if (!seed()) {
        return false;
    }
    buf.reserve(kPayloadSize);
    if (!payload(buf)) {
        return false;
    }
    if (!restore(buf.data(), buf.size())) {
        return false;
    }
    if (!sec()) {
        return false;
    }
    if (!imp()) {
        return false;
    }
    if (!proxy()) {
        return false;
    }
    if (!png()) {
        return false;
    }
    if (!lua()) {
        return false;
    }
    if (!tray()) {
        return false;
    }
    QueryPerformanceCounter(&g_T1);
    st = BCryptOpenAlgorithmProvider(&g_Hash, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st >= 0) {
        st = BCryptGetProperty(g_Hash, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&g_HashObj), sizeof(g_HashObj), &got, 0);
    }
    if (st < 0 || got != sizeof(g_HashObj) || g_HashObj == 0 || g_HashObj > 1024) {
        return false;
    }
    if (!token(tok)) {
        return false;
    }
    *reinterpret_cast<volatile std::uint64_t *>(g_Base + off::kMux) = tok;
    if (!RtlAddFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(g_Base + off::kRuntime), off::kRtCount, reinterpret_cast<DWORD64>(g_Base))) {
        return false;
    }
    if (!epA(reinterpret_cast<const void *>(&entry))) {
        return false;
    }
    return true;
}

bool
prep()
{
    static LONG once = 0;
    HANDLE th;

    if (InterlockedCompareExchange(&once, 1, 0) != 0) {
        return true;
    }
    for (const std::uint32_t rva : off::kTls) {
        reinterpret_cast<TlsFn>(g_Base + rva)(g_Base, DLL_THREAD_ATTACH, nullptr);
    }
    if (!png() || !lua() || !hookIN()) {
        InterlockedExchange(&once, 0);
        return false;
    }
    g_Veh = AddVectoredExceptionHandler(1, veh);
    if (!g_Veh) {
        hookOUT();
        InterlockedExchange(&once, 0);
        return false;
    }
    if (kLoadMod) {
        th = CreateThread(nullptr, 0, lod, nullptr, 0, nullptr);
        if (th) {
            CloseHandle(th);
        }
    }
    return true;
}

bool
ep()
{
    auto *old = g_Base + off::kEpOrig;
    auto *site = old - 4;

    if (!jmpRel(site, g_Base + off::kEpNew, PAGE_EXECUTE_READ) || !cfg(site)) {
        return false;
    }
    if (!stack(old, site)) {
        return false;
    }
    return true;
}

extern "C" DWORD WINAPI
entry()
{
    if (!prep()) {
        return ERROR_DLL_INIT_FAILED;
    }
    return reinterpret_cast<EpFn>(g_Base + off::kEpNew)();
}

}
