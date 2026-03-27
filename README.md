# MHWILDS File Open Probe

`MHWILDS_FileOpenProbe` is the standalone probe / version proxy project used to study Monster Hunter Wilds pak loading and to prototype encrypted custom mod packaging.

The repository now contains a working pure-memory encrypted pak route on `main`.

The current successful backend is a WinAPI virtual-handle streaming path that serves decrypted bytes on demand from chunked `v2` `.mhwsmod` packages. It does not stage a full plaintext `.pak` to disk, and for the chunked format it does not need to keep the whole plaintext pak in memory.

Current encryption-format notes live in:

- `docs/encryption_flow_design.md`

The current goal is narrow:

- Let our proxy own the whole custom pak chain.
- Read REFramework's config to decide whether `pak_mods` should be included.
- Install our own same-point hooks on the patch-version and pak-open call sites.
- Map `reframework\pak_mods` first, then append our own pak paths after that.
- Keep the working pure-memory route as the primary encrypted-mod path while retaining older staging infrastructure as fallback code.

This project is not a REFramework fork. It is a separate `version.dll` proxy loaded by the game at process start.

## Current Status

What is already confirmed:

- REFramework custom pak loading only does path redirection.
- REFramework raises the patch upper bound, scans `pak_mods`, and rewrites requested pak paths.
- It does not provide an in-memory pak backend.
- Our proxy can now load encrypted `.mhwsmod` packages through a pure-memory route backed by WinAPI virtual handles plus on-demand slice decrypt.
- The working serving chain is `CreateFileW`, `ReadFile`, `SetFilePointerEx`, `GetFileSizeEx`, `GetFileType`, `GetFileInformationByHandle`, `GetFileInformationByHandleEx`, `NtQueryInformationFile`, `CreateFileMappingW`, `MapViewOfFile`, `CloseHandle`, plus the DirectStorage open interception used by the current backend.
- The successful encrypted path uses chunked `v2` / algorithm `4`, so arbitrary plaintext offsets can be decrypted without loading the full plaintext pak.
- Metadata fields are optional. Per-mod update checks only run when the package is authenticated and both `mod_version` and `update_url` are present.
- A bare single-DLL deployment without `mhwilds_virtual_pak_loader.ini` now defaults to the rf-chain route instead of a no-op config.
- The old staged-path code is still present in the repository, but it is no longer the main encrypted-mod path on `main`.

Known limits of the current pure-memory implementation:

- The current success path is still the WinAPI virtual backend, not the native game stream functions.
- Native `OpenFileOrResourceStream` and `ReadFileOrResourceStream` hooks remain probe / logging hooks only.
- `CreateFileMappingW` support for slice-backed handles is still narrower than the ordinary `ReadFile` path, so the proven deployment route is the confirmed streaming path already exercised by the game.

## Branch Status

- `main`
  - Current recommended branch.
  - Encrypted `.mhwsmod` files now load through the pure-memory on-demand decrypt route.
  - The loader keeps the old staging infrastructure in the tree, but the successful encrypted-mod path on this branch does not depend on plaintext temp staging.
  - Metadata fields are optional. Per-mod update checks only run when the package is authenticated and both `mod_version` and `update_url` are present.
  - A bare single-DLL deployment without `mhwilds_virtual_pak_loader.ini` defaults to the rf-chain route instead of a no-op config.
- `wip/ntreadfile-backed-experiment-20260326`
  - Older pure-memory experiment checkpoint.
  - Kept because it captures earlier reverse-engineering state and hook layout.
  - Not the recommended deployment branch.

## Project Layout

The loader code is now a normal multi-translation-unit C++ layout. `src/plugin.cpp` stays thin and the actual implementation lives in `src/plugin/*.cpp`, with shared declarations centralized in one internal header.

### Top-Level Files

- `src/plugin.cpp`
  - Thin entry / export file.
  - Holds the `version.dll` proxy exports and `DllMain`.
- `src/plugin/plugin_internal.hpp`
  - Shared internal declarations for the loader.
  - Centralizes common includes, constants, structs, globals, and cross-module function declarations.
- `src/packer.cpp`
  - Native packer for producing the encrypted `.mhwsmod` container.
- `tools/make_mhwsmod.py`
  - Thin Python wrapper around the native packer executable.
- `src/version_proxy.def`
  - Export map for the `version.dll` proxy target.
- `include/encrypted_pak_format.hpp`
  - On-disk encrypted container format.
- `include/reframework_plugin_minimal.hpp`
  - Minimal REFramework plugin ABI definitions.

### Loader Modules

- `src/plugin/00_state_and_preamble.cpp`
  - Shared state, constants, globals, and basic path/log helpers.
- `src/plugin/10_redirect_and_path.cpp`
  - Patch-slot redirect logic, patch-version handling, path parsing, and low-level helpers.
- `src/plugin/20_hw_trace.cpp`
  - VEH and hardware-breakpoint instruction tracing.
- `src/plugin/30_config_and_crypto.cpp`
  - Config loading, key derivation, AES decrypt flow, and payload loading.
- `src/plugin/40_matching_and_tracking.cpp`
  - Target matching, caller/handle tracking, and bookkeeping.
- `src/plugin/50_virtual_fs_and_hooks.cpp`
  - Virtual file semantics and Win32 hook bodies.
- `src/plugin/60_bootstrap_and_shutdown.cpp`
  - Hook installation, bootstrap sequencing, retry logic, and cleanup.
- `src/plugin/70_update_check.cpp`
  - Loader / mod update check flow and prompt helpers.

The refactor is structural and behavioral: the old `inl` aggregation has been removed, and the project now builds as real `h + cpp` translation units.

## Build

```powershell
cmake -S G:\MHWILDS_FileOpenProbe -B G:\MHWILDS_FileOpenProbe\build -G "Visual Studio 17 2022" -A x64
cmake --build G:\MHWILDS_FileOpenProbe\build --config Release
```

No-log build:

```powershell
cmake -S G:\MHWILDS_FileOpenProbe -B G:\MHWILDS_FileOpenProbe\build_nolog -G "Visual Studio 17 2022" -A x64 -DMHWILDS_DISABLE_LOGGING=ON
cmake --build G:\MHWILDS_FileOpenProbe\build_nolog --config Release
```

Build outputs:

- `build\Release\version.dll`
- `build\Release\mhwilds_pak_packer.exe`
- `build_nolog\Release\version.dll`
- `build_nolog\Release\mhwilds_pak_packer.exe`

Author-side packager frontend:

```powershell
dotnet build G:\MHWILDS_FileOpenProbe\dotnet\MHWILDS.ModPackager\MHWILDS.ModPackager.csproj
```

Frontend output:

- `dotnet\MHWILDS.ModPackager\bin\Debug\net8.0-windows\MHWILDS.ModPackager.exe`

Default configurable paths in `CMakeLists.txt`:

- `MINHOOK_DIR`
- `MHWILDS_GAME_DIR`

## Author Packager

The repository now also contains a minimal Windows author tool:

- `dotnet\MHWILDS.ModPackager`

Current workflow:

1. Select `MonsterHunterWilds.exe`
2. Select an input source in a single field:
   - a loose-file mod folder that contains `natives/...`
   - or an existing `.pak`
3. Confirm or override the output `.mhwsmod` path
4. Optionally fill:
   - mod version
   - update source URL
   - author

The tool then:

1. builds a plain RE Engine `pak` from loose files when the input is a directory
2. skips that step when the input is already a `.pak`
3. calls `mhwilds_pak_packer.exe`
4. produces the final encrypted `.mhwsmod`

Default output location:

- `<packager exe directory>\output\`

Current metadata contract is intentionally minimal and fully optional:

- `mod_version`
- `update_url`
- `author`

If the metadata fields are left empty, later per-mod update checks should skip that package.

## Runtime Config

Example config:

- `mhwilds_virtual_pak_loader.ini.example`

Typical deployed config path for the proxy build:

- `E:\SteamLibrary\steamapps\common\MonsterHunterWilds\mhwilds_virtual_pak_loader.ini`

Important fields:

- `enabled`
- `mode`
- `source_path`
- `custom_pak_dir`
- `trace_enabled`
- `trace_start_rva`
- `trace_max_instructions`

The current same-point extension experiment typically uses:

- `mode=rf_chain`
- `custom_pak_dir=<directory that contains our extra .pak files>`

If `custom_pak_dir` is omitted, the proxy falls back to `<game root>\test_pak`.
If `re2_fw_config.txt` contains `IntegrityCheckBypass_LoadPakDirectory=true`, `<game root>\pak_mods` is inserted before `custom_pak_dir` / `test_pak` in the synthetic patch-slot order.
In the current prototype, `<game root>\pak_mods\*.mhwsmod` is also scanned. Those files are decrypted at startup into a per-launch randomized temp directory under the system temp root, with randomized non-`.pak` runtime filenames, then loaded through the same rf_chain path as ordinary custom paks. This staged plaintext path is the current usable path; it is not the unfinished pure-memory backend. Current direction is to prefer startup cleanup of stale leftovers rather than depending on detach-time cleanup.

Loader update gate fields:
The loader build version is baked into the DLL at build time. The current prototype checks a built-in update source URL, and if it reports a newer loader version, the `version.dll` proxy shows a message box and skips installing its pak-loading logic for that launch.

## Logs

Proxy logs:

- `mhwilds_version_proxy.log`
- `mhwilds_instruction_trace.log`

Current behavior:

- Each process launch truncates old logs.
- Instruction trace can now record:
  - entry trace
  - second-stage watch trace
  - module ownership for `rip` and branch targets
  - a small stack snapshot on watch hit
- If configured with `-DMHWILDS_DISABLE_LOGGING=ON`, the proxy does not create or write either log file.

## Confirmed REFramework Behavior

Relevant upstream file:

- `g:\REFramework\src\mods\IntegrityCheckBypass.cpp`

REFramework's custom pak route does three things:

1. Scans native patch files and raises the patch upper bound.
2. Scans `pak_mods` for custom `.pak` files.
3. Hooks the Win32 / DirectStorage pak-open route and rewrites the requested pak path to a custom pak path.

It does not implement an in-memory pak backend.

Our current proxy now mirrors the directory-scan contract itself for testing:

1. Scan native patch files.
2. Optionally scan `<game root>\pak_mods` if REFramework's config enables it.
3. Scan `<game root>\pak_mods\*.mhwsmod` and stage them into randomized temp `.pak` files.
4. Scan `custom_pak_dir` / `test_pak`.
5. Raise the patch upper bound by the combined count.
6. Rewrite synthetic patch-slot paths to the combined source list.

## Known Reverse-Engineering Conclusions

- Producer-side request setup was traced through the game executable path around:
  - `MonsterHunterWilds.exe + 0xA46D14D`
  - `MonsterHunterWilds.exe + 0x18DA1111`
- That producer path allocates / links request structures, but it is not the final payload copy.
- Later watch hits showed asynchronous consumer-side writes from another thread.
- Those later hits resolved into `dinput8.dll` in this environment.
- Therefore, once REFramework is in the chain, later post-redirection behavior cannot be analyzed as "pure game code only."

## Why The Current Backend Likely Fails

The current pure-memory synthetic-file backend probably still misses one or more of these:

- a real file-object invariant that causes the virtual handle path to be closed or rejected earlier than the plaintext baseline
- file-information semantics
- mapping semantics
- expected ordering between open / query / map / read paths
- asynchronous completion behavior across the later `NtReadFile` / `ReadFile` consumer chain
- a later chain that still assumes a real underlying file object
- an interaction introduced by REFramework's own `dinput8.dll` route
- a baseline behavior where matching a few sampled read bytes is still insufficient because the bytes are delivered under the wrong backend state or lifecycle

That is the current bottleneck, not pak-path discovery.

## Practical Next Step

When resuming work, start from this question:

"After REFramework rewrites the pak path, what exact file / mapping / backend invariants must still hold so that the game accepts our bytes without a plaintext pak on disk?"

Do not restart from loose-file loading or from REFramework path-discovery work. Those parts are already settled enough.
