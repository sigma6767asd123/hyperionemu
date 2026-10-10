#include "emulator/common.h"

#include "resource.h"
#include "mem7z.h"

#include <cstring>
#include <vector>

namespace emu {
namespace {

constexpr unsigned char kPngOld[7] = {0x44, 0x8b, 0x65, 0xd0, 0x45, 0x0b, 0xe2};
constexpr unsigned char kPngNew[7] = {0x6a, 0x07, 0x41, 0x5c, 0x90, 0x90, 0x90};
constexpr unsigned char kLuaOld[10] = {0x40, 0x53, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0xda, 0x48};
constexpr unsigned char kLuaNew[10] = {0xc7, 0x02, 0x07, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xc2, 0xc3};
constexpr unsigned char kTraySpawnOld[6] = {0xff, 0x15, 0x68, 0x7d, 0x9f, 0x05};
constexpr unsigned char kTraySpawnNew[6] = {0x31, 0xc0, 0x90, 0x90, 0x90, 0x90};
constexpr unsigned char kTrayCloseOld[6] = {0x0f, 0x84, 0xfb, 0x00, 0x00, 0x00};
constexpr unsigned char kTrayCloseNew[6] = {0xe9, 0xfb, 0x00, 0x00, 0x00, 0x90};

bool
poke(void *Slot, const void *Val, std::size_t Size)
{
    DWORD old = 0;
    DWORD tmp = 0;

    if (!VirtualProtect(Slot, Size, PAGE_READWRITE, &old)) {
        return false;
    }
    std::memcpy(Slot, Val, Size);
    if (!VirtualProtect(Slot, Size, old, &tmp)) {
        return false;
    }
    return true;
}

bool
secName(const IMAGE_SECTION_HEADER &Sh, const char *Name)
{
    return std::strncmp(reinterpret_cast<const char *>(Sh.Name), Name, IMAGE_SIZEOF_SHORT_NAME) == 0;
}

bool
patch(unsigned char *At, const unsigned char *Old, const unsigned char *Neu, std::size_t Size)
{
    if (std::memcmp(At, Neu, Size) == 0) {
        return true;
    }
    if (std::memcmp(At, Old, Size) != 0 || !wr(At, Neu, Size, PAGE_EXECUTE_READ)) {
        return false;
    }
    return std::memcmp(At, Neu, Size) == 0;
}

}

bool
img()
{
    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(g_Base);
    IMAGE_NT_HEADERS64 *nt;

    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return false;
    }
    nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(g_Base + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
           nt->OptionalHeader.SizeOfImage == kImageSize && nt->OptionalHeader.AddressOfEntryPoint == off::kEpOrig;
}

bool
payload(std::vector<unsigned char> &Out)
{
    const HRSRC res = FindResourceW(g_Self, MAKEINTRESOURCEW(IDR_PAYLOAD), RT_RCDATA);
    HGLOBAL handle;
    const unsigned char *raw;
    DWORD packed;

    if (!res) {
        return false;
    }
    packed = SizeofResource(g_Self, res);
    if (!packed) {
        return false;
    }
    handle = LoadResource(g_Self, res);
    if (!handle) {
        return false;
    }
    raw = static_cast<const unsigned char *>(LockResource(handle));
    if (!raw) {
        return false;
    }
    Out.resize(kPayloadSize);
    if (!Mem7zExtract(raw, packed, Out.data(), Out.size())) {
        Out.clear();
        return false;
    }
    return true;
}

bool
restore(const unsigned char *Payload, std::size_t Size)
{
    std::uint64_t count = 0;
    alignas(16) unsigned char zero[kTextPad]{};

    if (!Payload || Size != kPayloadSize) {
        return false;
    }
    std::memcpy(&count, Payload + kRtOff, sizeof(count));
    if (count != off::kRtCount) {
        return false;
    }
    if (!wr(g_Base + kTextRva, Payload, kTextMap, PAGE_EXECUTE_READ)) {
        return false;
    }
    if (!wr(g_Base + kTextRva + kTextMap, zero, sizeof(zero), PAGE_EXECUTE_READ)) {
        return false;
    }
    if (!wr(g_Base + off::kRuntime, Payload + kRtOff + sizeof(count), kRtSize, PAGE_READONLY)) {
        return false;
    }
    return true;
}

bool
sec()
{
    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(g_Base);
    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(g_Base + dos->e_lfanew);
    auto *sh = IMAGE_FIRST_SECTION(nt);
    bool text = false;
    bool tempest = false;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD old = 0;
        DWORD tmp = 0;
        const bool isText = secName(sh[i], ".text");
        const bool isTempest = secName(sh[i], "tempest");

        if (!isText && !isTempest) {
            continue;
        }
        if (!VirtualProtect(&sh[i].Characteristics, sizeof(sh[i].Characteristics), PAGE_READWRITE, &old)) {
            return false;
        }
        sh[i].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        VirtualProtect(&sh[i].Characteristics, sizeof(sh[i].Characteristics), old, &tmp);
        text |= isText;
        tempest |= isTempest;
    }
    return text && tempest;
}

bool
imp()
{
    const char *last = nullptr;
    HMODULE mod = nullptr;

    for (const auto &it : off::kImports) {
        FARPROC addr;

        if (!last || std::strcmp(last, it.Mod) != 0) {
            last = it.Mod;
            mod = GetModuleHandleA(it.Mod);
            if (!mod) {
                mod = LoadLibraryExA(it.Mod, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            }
            if (!mod) {
                mod = LoadLibraryA(it.Mod);
            }
            if (!mod) {
                return false;
            }
        }
        addr = GetProcAddress(mod, it.Fn);
        if (!addr) {
            return false;
        }
        if constexpr (kRandHwid) {
            if (std::strcmp(it.Fn, "GetSystemFirmwareTable") == 0) {
                g_Firmware = reinterpret_cast<FirmwareFn>(addr);
                addr = reinterpret_cast<FARPROC>(&firmware);
            } else if (std::strcmp(it.Fn, "GetAdaptersAddresses") == 0) {
                g_Adapters = reinterpret_cast<AdaptersFn>(addr);
                addr = reinterpret_cast<FARPROC>(&adapters);
            }
        }
        if (!poke(g_Base + it.Rva, &addr, sizeof(addr))) {
            return false;
        }
    }
    return !kRandHwid || (g_Firmware && g_Adapters);
}

bool
token(std::uint64_t &Out)
{
    NTSTATUS st;

    Out = 0;
    st = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&Out), sizeof(Out), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st >= 0 && Out != 0;
}

bool
proxy()
{
    auto *p = g_Base + off::kProxy;

    if (*p > 1) {
        return false;
    }
    *p = 0;
    return true;
}

bool
png()
{
    auto *p = g_Base + off::kPng;

    return patch(p, kPngOld, kPngNew, sizeof(kPngOld));
}

bool
lua()
{
    auto *p = g_Base + off::kLua;

    return patch(p, kLuaOld, kLuaNew, sizeof(kLuaOld));
}

bool
tray()
{
    auto *spawn = g_Base + off::kTraySpawn;
    auto *close = g_Base + off::kTrayClose;

    if constexpr (!kCloseInsteadOfTray) {
        return true;
    }
    if (std::memcmp(spawn, kTraySpawnOld, sizeof(kTraySpawnOld)) != 0 ||
        std::memcmp(close, kTrayCloseOld, sizeof(kTrayCloseOld)) != 0) {
        return false;
    }
    return wr(spawn, kTraySpawnNew, sizeof(kTraySpawnNew), PAGE_EXECUTE_READ) &&
           wr(close, kTrayCloseNew, sizeof(kTrayCloseNew), PAGE_EXECUTE_READ);
}

}
