<p align="center">
  <img src="logo.png" width="400">
</p>

# swift-mem

single-header direct syscall memory library with page caching for windows. made by yeezu. currently in beta, been working on this for a while, more updates coming.

bypasses ntdll and kernel32 entirely - generates raw syscall stubs at runtime with the correct SSN baked in. if ntdll is hooked (anti-cheat), falls back to halo's gate to resolve SSNs from neighboring unhooked stubs.

the page cache is what makes it actually fast. 4-way set-associative cache that pulls entire 4KB pages. every subsequent read on a cached page is just a memcpy - no syscall, no kernel transition. adaptive prefetching detects sequential access and pulls ahead pages automatically.

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
// default: 256 slots, 4-way, prefetch 2 pages ahead
if (!swift::init()) return 1;

// or configure the cache
swift::cache_config cfg;
cfg.slots = 1024;   // more slots = fewer collisions
cfg.ways  = 4;      // 4-way set-associative
cfg.prefetch_ahead = 2;
if (!swift::init(cfg)) return 1;

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

// try_read - distinguish failed reads from valid zeros
auto hp = swift::try_read<int>(base + 0x100);
if (hp.ok) printf("health: %d\n", hp.value);

// read arrays efficiently (uses cache, handles page boundaries)
float matrix[16];
swift::read_array<float>(view_matrix_addr, matrix, 16);

// pointer chains
uintptr_t player = swift::chain(base, {0x10, 0x20, 0x8});

// read MSVC std::string from target (handles SSO)
std::string name = swift::read_msvc_string(player + 0x70);
```

### writing

```cpp
swift::write<int>(base + 0x123, 100);
// automatically invalidates the cache for that page

// batch writes
uintptr_t addrs[] = {addr1, addr2, addr3};
const void* bufs[] = {&val1, &val2, &val3};
size_t sizes[] = {sizeof(val1), sizeof(val2), sizeof(val3)};
swift::write_batch(addrs, bufs, sizes, 3);
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

### multi-process

for reading multiple processes, use `swift::context` directly:

```cpp
swift::context game, overlay;
game.init();
overlay.init({.slots = 128, .ways = 2});

game.attach(L"game.exe");
overlay.attach(L"overlay.exe");

int hp = game.read<int>(addr);
// each context has its own cache, handle, syscall stubs
```

the free functions (`swift::read`, `swift::attach` etc) are shortcuts that use a default global context. same API, just without the object.

### cleanup

```cpp
swift::cleanup();
// or let context destructor handle it (RAII)
```

## api

- `init(cfg)` / `cleanup()` - setup and teardown (RAII supported)
- `attach(name)` / `attach(pid)` - open target process
- `detach()` - close handle
- `read<T>(addr)` - cached read
- `try_read<T>(addr)` - cached read with success/fail status
- `read_volatile<T>(addr)` - uncached read
- `read_array<T>(addr, out, count)` - read contiguous array
- `write<T>(addr, val)` - write + cache invalidate
- `write_batch(...)` - multiple writes
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
- RAII - context cleans up on destruction, no leaks
- more features and optimizations coming
