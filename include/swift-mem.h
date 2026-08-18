#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <initializer_list>
#include <Windows.h>
#include <TlHelp32.h>

namespace swift {

struct cache_config {
    size_t slots = 256;
    size_t ways  = 4;
    size_t prefetch_ahead = 2;
};

template<typename T>
struct result {
    T value;
    bool ok;
    operator bool() const { return ok; }
    T operator*() const { return value; }
};

namespace detail {

using fn_NtRVM = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using fn_NtWVM = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

static constexpr size_t PAGE_SIZE = 0x1000;
static constexpr size_t PAGE_MASK = ~(PAGE_SIZE - 1);

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

struct cache_line {
    uintptr_t page_base;
    uint64_t  frame;
    uint8_t   data[PAGE_SIZE];
};

} // detail

class context {
    HANDLE   m_proc   = nullptr;
    uint32_t m_pid    = 0;
    uint8_t* m_stub   = nullptr;

    detail::fn_NtRVM m_read_fn  = nullptr;
    detail::fn_NtWVM m_write_fn = nullptr;

    detail::cache_line* m_cache = nullptr;
    size_t   m_sets     = 0;
    size_t   m_ways     = 0;
    size_t   m_prefetch = 0;
    uint64_t m_frame    = 0;
    bool     m_cache_on = true;

    uintptr_t m_last_fill = 0;

    __forceinline size_t set_index(uintptr_t page) const {
        return (page >> 12) & (m_sets - 1);
    }

    __forceinline detail::cache_line* cache_find(uintptr_t page) {
        auto* set = &m_cache[set_index(page) * m_ways];
        for (size_t w = 0; w < m_ways; w++)
            if (set[w].page_base == page && set[w].frame == m_frame) return &set[w];
        return nullptr;
    }

    __forceinline detail::cache_line* cache_fill_one(uintptr_t page, bool speculative = false) {
        auto* set = &m_cache[set_index(page) * m_ways];
        size_t victim = 0;
        uint64_t oldest = set[0].frame;
        for (size_t w = 1; w < m_ways; w++) {
            if (set[w].frame < oldest) { oldest = set[w].frame; victim = w; }
        }
        // don't evict a live line for speculative prefetch
        if (speculative && oldest == m_frame) return nullptr;

        uint8_t tmp[detail::PAGE_SIZE];
        auto* buf = speculative ? tmp : set[victim].data;
        if (m_read_fn(m_proc, reinterpret_cast<PVOID>(page), buf, detail::PAGE_SIZE, nullptr) != 0)
            return nullptr;
        if (speculative) memcpy(set[victim].data, tmp, detail::PAGE_SIZE);
        set[victim].page_base = page;
        set[victim].frame = m_frame;
        return &set[victim];
    }

    __forceinline detail::cache_line* cache_fill(uintptr_t page) {
        auto* line = cache_fill_one(page);
        if (!line) return nullptr;

        if (m_prefetch > 0 && page == m_last_fill + detail::PAGE_SIZE) {
            for (size_t i = 1; i <= m_prefetch; i++) {
                uintptr_t ahead = page + i * detail::PAGE_SIZE;
                if (!cache_find(ahead)) cache_fill_one(ahead, true);
            }
        }
        m_last_fill = page;
        return line;
    }

    void invalidate_page(uintptr_t page) {
        auto* set = &m_cache[set_index(page) * m_ways];
        for (size_t w = 0; w < m_ways; w++)
            if (set[w].page_base == page) set[w].frame = 0;
    }

public:
    context() = default;
    ~context() { cleanup(); }

    context(const context&) = delete;
    context& operator=(const context&) = delete;

    context(context&& o) noexcept
        : m_proc(o.m_proc), m_pid(o.m_pid), m_stub(o.m_stub),
          m_read_fn(o.m_read_fn), m_write_fn(o.m_write_fn),
          m_cache(o.m_cache), m_sets(o.m_sets), m_ways(o.m_ways),
          m_prefetch(o.m_prefetch), m_frame(o.m_frame),
          m_cache_on(o.m_cache_on), m_last_fill(o.m_last_fill) {
        o.m_proc = nullptr; o.m_stub = nullptr; o.m_cache = nullptr;
        o.m_read_fn = nullptr; o.m_write_fn = nullptr;
    }

    context& operator=(context&& o) noexcept {
        if (this != &o) { cleanup(); new(this) context(std::move(o)); }
        return *this;
    }

    bool init(cache_config cfg = {}) {
        m_stub = reinterpret_cast<uint8_t*>(
            VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!m_stub) return false;

        auto ssn_r = detail::resolve_ssn("NtReadVirtualMemory");
        auto ssn_w = detail::resolve_ssn("NtWriteVirtualMemory");
        if (!ssn_r || !ssn_w) {
            VirtualFree(m_stub, 0, MEM_RELEASE); m_stub = nullptr;
            return false;
        }

        auto* cur = m_stub;
        m_read_fn  = reinterpret_cast<detail::fn_NtRVM>(detail::make_stub(cur, ssn_r));
        m_write_fn = reinterpret_cast<detail::fn_NtWVM>(detail::make_stub(cur, ssn_w));

        m_ways = cfg.ways < 1 ? 1 : cfg.ways;
        size_t total = cfg.slots < m_ways ? m_ways : cfg.slots;
        m_sets = 1;
        while (m_sets < total / m_ways) m_sets <<= 1;
        if (m_sets == 0 || (m_sets & (m_sets - 1)) != 0) {
            VirtualFree(m_stub, 0, MEM_RELEASE); m_stub = nullptr;
            return false;
        }

        m_cache = new detail::cache_line[m_sets * m_ways]{};
        m_prefetch = cfg.prefetch_ahead;
        m_frame = 1;
        return true;
    }

    bool attach(const wchar_t* name) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
        m_pid = 0;
        if (Process32FirstW(snap, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, name) == 0) { m_pid = entry.th32ProcessID; break; }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
        if (!m_pid) return false;
        m_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
        return m_proc != nullptr;
    }

    bool attach(uint32_t pid) {
        m_pid = pid;
        m_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        return m_proc != nullptr;
    }

    void detach() {
        if (m_proc) CloseHandle(m_proc);
        m_proc = nullptr; m_pid = 0;
    }

    void cleanup() {
        detach();
        if (m_stub) { VirtualFree(m_stub, 0, MEM_RELEASE); m_stub = nullptr; }
        if (m_cache) { delete[] m_cache; m_cache = nullptr; }
        m_read_fn = nullptr; m_write_fn = nullptr;
    }

    __forceinline void new_frame() { m_frame++; }
    void set_cache(bool on) { m_cache_on = on; }

    __forceinline bool read_raw(uintptr_t addr, void* buf, size_t sz) {
        return m_read_fn(m_proc, reinterpret_cast<PVOID>(addr), buf, sz, nullptr) == 0;
    }

    template<typename T>
    __forceinline T read(uintptr_t addr) {
        if (m_cache_on) {
            uintptr_t page = addr & detail::PAGE_MASK;
            size_t off = addr & (detail::PAGE_SIZE - 1);
            if (off + sizeof(T) <= detail::PAGE_SIZE) {
                auto* line = cache_find(page);
                if (!line) line = cache_fill(page);
                if (line) { T v; memcpy(&v, line->data + off, sizeof(T)); return v; }
            }
        }
        T v{}; m_read_fn(m_proc, reinterpret_cast<PVOID>(addr), &v, sizeof(T), nullptr); return v;
    }

    template<typename T>
    __forceinline result<T> try_read(uintptr_t addr) {
        if (m_cache_on) {
            uintptr_t page = addr & detail::PAGE_MASK;
            size_t off = addr & (detail::PAGE_SIZE - 1);
            if (off + sizeof(T) <= detail::PAGE_SIZE) {
                auto* line = cache_find(page);
                if (!line) line = cache_fill(page);
                if (line) { T v; memcpy(&v, line->data + off, sizeof(T)); return {v, true}; }
            }
        }
        T v{};
        bool ok = m_read_fn(m_proc, reinterpret_cast<PVOID>(addr), &v, sizeof(T), nullptr) == 0;
        return {v, ok};
    }

    template<typename T>
    __forceinline T read_volatile(uintptr_t addr) {
        T v{}; m_read_fn(m_proc, reinterpret_cast<PVOID>(addr), &v, sizeof(T), nullptr); return v;
    }

    template<typename T>
    bool read_array(uintptr_t addr, T* out, size_t count) {
        size_t total = count * sizeof(T);

        if (!m_cache_on || total > detail::PAGE_SIZE * 4)
            return read_raw(addr, out, total);

        auto* dst = reinterpret_cast<uint8_t*>(out);
        size_t remaining = total;
        uintptr_t cur = addr;

        while (remaining > 0) {
            uintptr_t page = cur & detail::PAGE_MASK;
            size_t off = cur & (detail::PAGE_SIZE - 1);
            size_t chunk = detail::PAGE_SIZE - off;
            if (chunk > remaining) chunk = remaining;

            auto* line = cache_find(page);
            if (!line) line = cache_fill(page);
            if (line) {
                memcpy(dst, line->data + off, chunk);
            } else {
                if (!read_raw(cur, dst, chunk)) return false;
            }
            dst += chunk; cur += chunk; remaining -= chunk;
        }
        return true;
    }

    __forceinline bool write_raw(uintptr_t addr, const void* buf, size_t sz) {
        return m_write_fn(m_proc, reinterpret_cast<PVOID>(addr), const_cast<void*>(buf), sz, nullptr) == 0;
    }

    template<typename T>
    __forceinline bool write(uintptr_t addr, const T& val) {
        invalidate_page(addr & detail::PAGE_MASK);
        return m_write_fn(m_proc, reinterpret_cast<PVOID>(addr), const_cast<T*>(&val), sizeof(T), nullptr) == 0;
    }

    size_t write_batch(const uintptr_t* addrs, const void* const* bufs, const size_t* sizes, size_t count) {
        size_t ok = 0;
        for (size_t i = 0; i < count; i++) {
            invalidate_page(addrs[i] & detail::PAGE_MASK);
            if (m_write_fn(m_proc, reinterpret_cast<PVOID>(addrs[i]), const_cast<void*>(bufs[i]), sizes[i], nullptr) == 0)
                ok++;
        }
        return ok;
    }

    std::string read_string(uintptr_t addr, size_t max_len = 256) {
        std::string buf(max_len, '\0');
        if (!read_raw(addr, buf.data(), max_len)) return "";
        buf.resize(strnlen(buf.c_str(), max_len));
        return buf;
    }

    std::string read_msvc_string(uintptr_t str_addr) {
        if (!str_addr) return "";
        auto len_r = try_read<int32_t>(str_addr + 0x10);
        if (!len_r || len_r.value <= 0 || len_r.value > 255) return "";
        uintptr_t buf_addr = (len_r.value < 16) ? str_addr : read<uintptr_t>(str_addr);
        if (!buf_addr) return "";
        return read_string(buf_addr, len_r.value);
    }

    uintptr_t get_module_base(const wchar_t* mod) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
        uintptr_t base = 0;
        if (Module32FirstW(snap, &entry)) {
            do {
                if (_wcsicmp(entry.szModule, mod) == 0) { base = reinterpret_cast<uintptr_t>(entry.modBaseAddr); break; }
            } while (Module32NextW(snap, &entry));
        }
        CloseHandle(snap);
        return base;
    }

    uintptr_t chain(uintptr_t base, std::initializer_list<uintptr_t> offsets) {
        uintptr_t addr = base;
        for (auto off : offsets) { addr = read<uintptr_t>(addr + off); if (!addr) return 0; }
        return addr;
    }

    size_t batch_read(const uintptr_t* addrs, void** bufs, const size_t* sizes, size_t count) {
        size_t ok = 0;
        for (size_t i = 0; i < count; i++)
            if (read_raw(addrs[i], bufs[i], sizes[i])) ok++;
        return ok;
    }

    uint32_t pid() const { return m_pid; }
    HANDLE handle() const { return m_proc; }
};

// global convenience - backward compatible free functions wrapping a default context
namespace detail { inline context g_ctx; }

inline bool init(cache_config cfg = {}) { return detail::g_ctx.init(cfg); }
inline bool attach(const wchar_t* name) { return detail::g_ctx.attach(name); }
inline bool attach(uint32_t pid) { return detail::g_ctx.attach(pid); }
inline void detach() { detail::g_ctx.detach(); }
inline void cleanup() { detail::g_ctx.cleanup(); }
inline void new_frame() { detail::g_ctx.new_frame(); }
inline void set_cache(bool on) { detail::g_ctx.set_cache(on); }

inline bool read_raw(uintptr_t addr, void* buf, size_t sz) { return detail::g_ctx.read_raw(addr, buf, sz); }
template<typename T> __forceinline T read(uintptr_t addr) { return detail::g_ctx.read<T>(addr); }
template<typename T> __forceinline result<T> try_read(uintptr_t addr) { return detail::g_ctx.try_read<T>(addr); }
template<typename T> __forceinline T read_volatile(uintptr_t addr) { return detail::g_ctx.read_volatile<T>(addr); }
template<typename T> bool read_array(uintptr_t addr, T* out, size_t count) { return detail::g_ctx.read_array(addr, out, count); }

inline bool write_raw(uintptr_t addr, const void* buf, size_t sz) { return detail::g_ctx.write_raw(addr, buf, sz); }
template<typename T> __forceinline bool write(uintptr_t addr, const T& val) { return detail::g_ctx.write<T>(addr, val); }
inline size_t write_batch(const uintptr_t* addrs, const void* const* bufs, const size_t* sizes, size_t count) {
    return detail::g_ctx.write_batch(addrs, bufs, sizes, count);
}

inline std::string read_string(uintptr_t addr, size_t max_len = 256) { return detail::g_ctx.read_string(addr, max_len); }
inline std::string read_msvc_string(uintptr_t addr) { return detail::g_ctx.read_msvc_string(addr); }
inline uintptr_t get_module_base(const wchar_t* mod) { return detail::g_ctx.get_module_base(mod); }
inline uintptr_t chain(uintptr_t base, std::initializer_list<uintptr_t> offsets) { return detail::g_ctx.chain(base, offsets); }
inline size_t batch_read(const uintptr_t* addrs, void** bufs, const size_t* sizes, size_t count) {
    return detail::g_ctx.batch_read(addrs, bufs, sizes, count);
}

inline uint32_t pid() { return detail::g_ctx.pid(); }
inline HANDLE handle() { return detail::g_ctx.handle(); }

} // swift
