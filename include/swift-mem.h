#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

namespace swift {

namespace detail {

inline HANDLE g_process = nullptr;
inline uint32_t g_pid = 0;
inline uint8_t* g_stub_mem = nullptr;

using fn_NtRVM = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using fn_NtWVM = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

inline fn_NtRVM syscall_read = nullptr;
inline fn_NtWVM syscall_write = nullptr;

inline uint32_t resolve_ssn(const char* name) {
    auto ntdll = reinterpret_cast<uint8_t*>(GetModuleHandleA("ntdll.dll"));
    if (!ntdll) return 0;

    auto func = reinterpret_cast<uint8_t*>(GetProcAddress(reinterpret_cast<HMODULE>(ntdll), name));
    if (!func) return 0;

    // mov r10, rcx / mov eax, ssn
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8)
        return *reinterpret_cast<uint32_t*>(func + 4);

    // halo's gate
    for (uint32_t i = 1; i < 500; i++) {
        uint8_t* down = func + (i * 32);
        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8)
            return *reinterpret_cast<uint32_t*>(down + 4) - i;

        uint8_t* up = func - (i * 32);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8)
            return *reinterpret_cast<uint32_t*>(up + 4) + i;
    }
    return 0;
}

inline void* make_stub(uint8_t*& cursor, uint32_t ssn) {
    void* addr = cursor;
    cursor[0] = 0x49; cursor[1] = 0x89; cursor[2] = 0xCA;
    cursor[3] = 0xB8;
    *reinterpret_cast<uint32_t*>(cursor + 4) = ssn;
    cursor[8] = 0x0F; cursor[9] = 0x05;
    cursor[10] = 0xC3;
    cursor += 16;
    return addr;
}

static constexpr size_t PAGE_SIZE = 0x1000;
static constexpr size_t PAGE_MASK = ~(PAGE_SIZE - 1);
static constexpr size_t CACHE_SLOTS = 256;
static constexpr size_t CACHE_HASH_MASK = CACHE_SLOTS - 1;

struct cache_entry {
    uintptr_t page_base;
    uint64_t frame;
    uint8_t data[PAGE_SIZE];
};

inline cache_entry g_cache[CACHE_SLOTS]{};
inline uint64_t g_frame = 0;
inline bool g_cache_enabled = true;

__forceinline size_t page_hash(uintptr_t page_base) {
    return (page_base >> 12) & CACHE_HASH_MASK;
}

__forceinline cache_entry* cache_lookup(uintptr_t page_base) {
    auto* e = &g_cache[page_hash(page_base)];
    return (e->page_base == page_base && e->frame == g_frame) ? e : nullptr;
}

__forceinline cache_entry* cache_fill(uintptr_t page_base) {
    auto* e = &g_cache[page_hash(page_base)];
    if (syscall_read(g_process, reinterpret_cast<PVOID>(page_base), e->data, PAGE_SIZE, nullptr) != 0)
        return nullptr;
    e->page_base = page_base;
    e->frame = g_frame;
    return e;
}

} // detail

inline bool init() {
    detail::g_stub_mem = reinterpret_cast<uint8_t*>(
        VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    );
    if (!detail::g_stub_mem) return false;

    auto ssn_read = detail::resolve_ssn("NtReadVirtualMemory");
    auto ssn_write = detail::resolve_ssn("NtWriteVirtualMemory");
    if (!ssn_read || !ssn_write) {
        VirtualFree(detail::g_stub_mem, 0, MEM_RELEASE);
        detail::g_stub_mem = nullptr;
        return false;
    }

    auto* cursor = detail::g_stub_mem;
    detail::syscall_read = reinterpret_cast<detail::fn_NtRVM>(detail::make_stub(cursor, ssn_read));
    detail::syscall_write = reinterpret_cast<detail::fn_NtWVM>(detail::make_stub(cursor, ssn_write));
    memset(detail::g_cache, 0, sizeof(detail::g_cache));
    return true;
}

__forceinline void new_frame() { detail::g_frame++; }

inline void set_cache(bool enabled) { detail::g_cache_enabled = enabled; }

inline bool attach(const wchar_t* process_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    detail::g_pid = 0;

    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, process_name) == 0) {
                detail::g_pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);

    if (!detail::g_pid) return false;
    detail::g_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, detail::g_pid);
    return detail::g_process != nullptr;
}

inline bool attach(uint32_t pid) {
    detail::g_pid = pid;
    detail::g_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    return detail::g_process != nullptr;
}

inline void detach() {
    if (detail::g_process) CloseHandle(detail::g_process);
    detail::g_process = nullptr;
    detail::g_pid = 0;
}

inline void cleanup() {
    detach();
    if (detail::g_stub_mem) {
        VirtualFree(detail::g_stub_mem, 0, MEM_RELEASE);
        detail::g_stub_mem = nullptr;
    }
    detail::syscall_read = nullptr;
    detail::syscall_write = nullptr;
}

__forceinline bool read_raw(uintptr_t address, void* buffer, size_t size) {
    return detail::syscall_read(detail::g_process, reinterpret_cast<PVOID>(address), buffer, size, nullptr) == 0;
}

__forceinline bool write_raw(uintptr_t address, const void* buffer, size_t size) {
    return detail::syscall_write(detail::g_process, reinterpret_cast<PVOID>(address), const_cast<void*>(buffer), size, nullptr) == 0;
}

template<typename T>
__forceinline T read(uintptr_t address) {
    if (detail::g_cache_enabled) {
        uintptr_t page = address & detail::PAGE_MASK;
        size_t off = address & (detail::PAGE_SIZE - 1);

        if (off + sizeof(T) <= detail::PAGE_SIZE) {
            auto* e = detail::cache_lookup(page);
            if (!e) e = detail::cache_fill(page);
            if (e) {
                T val;
                memcpy(&val, e->data + off, sizeof(T));
                return val;
            }
        }
    }
    T val{};
    detail::syscall_read(detail::g_process, reinterpret_cast<PVOID>(address), &val, sizeof(T), nullptr);
    return val;
}

template<typename T>
__forceinline T read_volatile(uintptr_t address) {
    T val{};
    detail::syscall_read(detail::g_process, reinterpret_cast<PVOID>(address), &val, sizeof(T), nullptr);
    return val;
}

template<typename T>
__forceinline bool write(uintptr_t address, const T& val) {
    uintptr_t page = address & detail::PAGE_MASK;
    size_t slot = detail::page_hash(page);
    if (detail::g_cache[slot].page_base == page)
        detail::g_cache[slot].frame = 0;
    return detail::syscall_write(detail::g_process, reinterpret_cast<PVOID>(address), const_cast<T*>(&val), sizeof(T), nullptr) == 0;
}

inline std::string read_string(uintptr_t address, size_t max_len = 256) {
    std::string buf(max_len, '\0');
    if (!read_raw(address, buf.data(), max_len)) return "";
    buf.resize(strnlen(buf.c_str(), max_len));
    return buf;
}

inline std::string read_msvc_string(uintptr_t str_addr) {
    if (!str_addr) return "";
    int32_t len = read<int32_t>(str_addr + 0x10);
    if (len <= 0 || len > 255) return "";
    uintptr_t buf_addr = (len < 16) ? str_addr : read<uintptr_t>(str_addr);
    if (!buf_addr) return "";
    return read_string(buf_addr, len);
}

inline uintptr_t get_module_base(const wchar_t* mod) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, detail::g_pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    uintptr_t base = 0;

    if (Module32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, mod) == 0) {
                base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return base;
}

inline uintptr_t chain(uintptr_t base, std::initializer_list<uintptr_t> offsets) {
    uintptr_t addr = base;
    for (auto off : offsets) {
        addr = read<uintptr_t>(addr + off);
        if (!addr) return 0;
    }
    return addr;
}

inline size_t batch_read(const uintptr_t* addresses, void** buffers, const size_t* sizes, size_t count) {
    size_t ok = 0;
    for (size_t i = 0; i < count; i++)
        if (read_raw(addresses[i], buffers[i], sizes[i])) ok++;
    return ok;
}

inline uint32_t pid() { return detail::g_pid; }
inline HANDLE handle() { return detail::g_process; }

} // swift
