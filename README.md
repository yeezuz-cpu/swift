<p align="center">
  <img src="logo.png" width="400">
</p>

# swift-mem

single-header direct syscall memory library with page caching for windows. made by yeezu. currently in beta, been working on this for a while, more updates coming.

bypasses ntdll and kernel32 entirely - generates raw syscall stubs at runtime with the correct SSN baked in. if ntdll is hooked (anti-cheat), falls back to halo's gate to resolve SSNs from neighboring unhooked stubs.

the page cache is what makes it actually fast. on the first read swift-mem pulls an entire 4KB page into a local cache. every subsequent read on that same page is just a memcpy - no syscall, no kernel transition.

## performance

benchmarked cross-process against explorer.exe, 1M reads, 5 runs:

- **swift-mem cached vs ReadProcessMemory: ~411x faster**
- **swift-mem cached vs NtReadVirtualMemory: ~381x faster**
- realistic test (4 nearby struct fields per iteration): **~1500x faster than RPM**

uncached (no page cache, raw syscall only) is roughly on par with NtReadVirtualMemory - the speedup comes from the cache, not the syscall itself.

tested with a roblox external reading 100 players with box esp at 60fps - **2.2% CPU usage**.

## getting started

header-only. grab `include/swift-mem.h` and drop it into your project.

```cpp
#include "swift-mem.h"
```

### basic setup

```cpp
if (!swift::init()) return 1;
if (!swift::attach(L"game.exe")) return 1;

uintptr_t base = swift::get_module_base(L"game.exe");
```

### reading

```cpp
// cached - pulls 4KB page on first access, memcpy after
int health = swift::read<int>(base + 0x123);

// nearby reads on the same page hit the cache, no syscall
float x = swift::read<float>(base + 0x130);
float y = swift::read<float>(base + 0x134);
float z = swift::read<float>(base + 0x138);

// uncached - always syscalls, for volatile data
int ammo = swift::read_volatile<int>(base + 0x200);

// pointer chains
uintptr_t player = swift::chain(base, {0x10, 0x20, 0x8});

// read MSVC std::string from target (handles SSO)
std::string name = swift::read_msvc_string(player + 0x70);
```

### page cache

call `new_frame()` once per tick to invalidate stale pages:

```cpp
while (running) {
    swift::new_frame();

    // reads within a frame benefit from cache
    // one syscall per page instead of per read

    Sleep(16);
}
```

### writing

```cpp
swift::write<int>(base + 0x123, 100);
// automatically invalidates the cache for that page
```

### cleanup

```cpp
swift::cleanup();
```

## api

- `init()` / `cleanup()` - setup and teardown
- `attach(name)` / `attach(pid)` - open target process
- `detach()` - close handle
- `read<T>(addr)` - cached read
- `read_volatile<T>(addr)` - uncached read
- `write<T>(addr, val)` - write + cache invalidate
- `read_raw` / `write_raw` - raw bytes
- `read_string` / `read_msvc_string` - string helpers
- `chain(base, {offsets})` - pointer chain
- `batch_read(...)` - multiple reads
- `get_module_base(name)` - module base in target
- `new_frame()` - invalidate page cache
- `set_cache(bool)` - toggle caching
- `pid()` / `handle()` - get target pid/handle

## notes

- header-only, no dependencies beyond windows headers
- needs admin for process handles
- handles hooked ntdll via halo's gate
- hot path is `__forceinline`
- windows 10 and 11
- more features and optimizations coming
