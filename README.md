# MHWILDS File Open Probe

`MHWILDS_FileOpenProbe` is the standalone probe / version proxy project used to study Monster Hunter Wilds pak loading and to prototype a staged plaintext loader with encrypted custom mod packaging.

Current encryption-format notes live in:

- `docs/encryption_flow_design.md`

The current goal is narrow:

- Let our proxy own the whole custom pak chain.
- Read REFramework's config to decide whether `pak_mods` should be included.
- Install our own same-point hooks on the patch-version and pak-open call sites.
- Map `reframework\pak_mods` first, then append our own pak paths after that.

This project is not a REFramework fork. It is a separate DLL project that can be deployed either as:

- `version.dll` proxy loaded by the game at process start.
- `mhwilds_file_open_probe.dll` REFramework plugin build for lighter experiments.

## Current Status

What is already confirmed:

- REFramework custom pak loading only does path redirection.
- REFramework raises the patch upper bound, scans `pak_mods`, and rewrites requested pak paths.
- It does not provide an in-memory pak backend.
- Our proxy can intercept the later Win32 pak I/O chain and can return synthetic file semantics.
- Hardware-breakpoint tracing showed that later consumer-side activity touches request-owner state asynchronously.
- The traced consumer-side path lands inside the process `dinput8.dll`, which in this environment is REFramework's proxy layer.

The current implementation direction is different from the earlier same-point coexistence experiment:

- We no longer depend on REFramework's own redirect hook to service `pak_mods`.
- Our proxy reads `re2_fw_config.txt`, decides whether `IntegrityCheckBypass_LoadPakDirectory` is enabled, and then builds one combined custom pak chain:
  - `pak_mods\*.pak`
  - our own `custom_pak_dir` / `test_pak`

What is not solved yet:

- We still need to verify whether same-point `SafetyHook` hooks can coexist cleanly with REFramework in this specific pak-loading path.
- The current test build only targets explicit external pak paths first; temp staging and encryption will come later.

## Project Layout

The old single huge `src/plugin.cpp` has been flattened into a thin entry file plus implementation fragments under `src/plugin/`.

### Top-Level Files

- `src/plugin.cpp`
  - Thin entry file.
  - Keeps exports, `DllMain`, and includes the implementation fragments in order.
- `src/packer.cpp`
  - AES-based packer for producing the encrypted payload container used by the proxy.
- `tools/make_mhwsmod.py`
  - Thin Python wrapper around the native packer executable.
- `src/version_proxy.def`
  - Export map for the `version.dll` proxy target.
- `include/encrypted_pak_format.hpp`
  - On-disk encrypted container format.
- `include/reframework_plugin_minimal.hpp`
  - Minimal REFramework plugin ABI definitions.

### Implementation Fragments

- `src/plugin/00_state_and_preamble.inl`
  - Constants, structs, globals, shared state, basic path/log helpers.
- `src/plugin/10_redirect_and_path.inl`
  - Redirect breakpoints, patch-version breakpoint, path parsing, low-level helpers.
- `src/plugin/20_hw_trace.inl`
  - VEH + hardware-breakpoint trace pipeline, stack snapshot, multi-stage trace logic.
- `src/plugin/30_config_and_crypto.inl`
  - INI loading, AES decrypt path, key derivation, payload loading.
- `src/plugin/40_matching_and_tracking.inl`
  - Target matching, caller tracking, handle tracking, bookkeeping.
- `src/plugin/50_virtual_fs_and_hooks.inl`
  - Virtual file implementation and Win32 hook bodies.
- `src/plugin/60_bootstrap_and_shutdown.inl`
  - Hook install/bootstrap, retry logic, shutdown cleanup.

This is still intentionally one translation unit for now. The split is structural, not behavioral. That keeps the refactor low-risk while making the codebase easier to navigate.

## Build

```powershell
cmake -S G:\MHWILDS_FileOpenProbe -B G:\MHWILDS_FileOpenProbe\build -G "Visual Studio 17 2022" -A x64
cmake --build G:\MHWILDS_FileOpenProbe\build --config Release
```

Build outputs:

- `build\Release\version.dll`
- `build\Release\mhwilds_file_open_probe.dll`
- `build\Release\mhwilds_pak_packer.exe`

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
In the current prototype, `<game root>\pak_mods\*.mhwsmod` is also scanned. Those files are decrypted at startup into a per-launch randomized temp directory under the system temp root, with randomized non-`.pak` runtime filenames, then loaded through the same rf_chain path as ordinary custom paks. Current direction is to prefer startup cleanup of stale leftovers rather than depending on detach-time cleanup.

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

The current synthetic-file backend probably still misses one or more of these:

- file-information semantics
- mapping semantics
- expected ordering between open / query / map / read paths
- a later chain that still assumes a real underlying file object
- an interaction introduced by REFramework's own `dinput8.dll` route

That is the current bottleneck, not pak-path discovery.

## Practical Next Step

When resuming work, start from this question:

"After REFramework rewrites the pak path, what exact file / mapping / backend invariants must still hold so that the game accepts our bytes without a plaintext pak on disk?"

Do not restart from loose-file loading or from REFramework path-discovery work. Those parts are already settled enough.
