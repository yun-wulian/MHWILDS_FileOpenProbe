# Pure-Memory Pak Virtual File Plan

Last updated: 2026-03-26

## Purpose

This document is the continuity note for the pure-memory encrypted pak route in `G:\MHWILDS_FileOpenProbe`.
When resuming this project in a later context window, read this file first.

## Current Goal

Make custom encrypted `.mhwsmod` packages load through a pure-memory path without staging a decrypted runtime `.pak` on disk.
The target behavior is: the game believes it is talking to a normal plaintext pak file object, while we supply plaintext bytes on demand from the encrypted container.

## Stable Conclusions

1. The remaining black-screen failure is not explained by isolated payload corruption.
   Prior raw-byte comparisons showed plaintext and encrypted runs share the same payload set; the difference is sequence and multiplicity, not unique byte content.

2. The current blocker is file-object semantics, not chunk crypto.
   The game appears to change later read decisions based on what it observes from earlier I/O issue/completion state.

3. The current implementation is still a mixed model.
   It often returns the real encrypted backing handle to the game, then overlays virtual read state on top of it.
   This leaks real container-handle behavior and makes the game observe something other than a plaintext pak file object.

4. The current async path is synthetic worker/APC driven.
   That means completion timing and visibility are still not equivalent to the kernel-driven behavior of a real plaintext file handle.

5. Random-read support is not the hard blocker.
   The current format already has a chunked random-access view. The remaining work is to make the whole virtual file contract look like a plaintext pak to the game.

## Why The Current Backend Likely Fails

The current backend still differs from a real plaintext pak in at least these ways:

1. Real backing handle exposure.
   `create_virtual_file_handle(...)` currently prefers returning the real backing handle when opening the encrypted source succeeds.

2. Mixed position semantics.
   The code tracks virtual file position, but also tries to keep the backing handle's pointer in sync for non-synthetic handles.

3. Synthetic async completion model.
   Virtual `ReadFileEx` / `NtReadFile` requests are queued into internal worker threads and later completed through our own APC delivery path.

4. Early result publication.
   Some virtual async reads publish bytes or success-looking state at issue time based on heuristics, instead of strictly matching the externally observed behavior of a real plaintext pak handle.

## Target Model

The correct end-state is a pure synthetic virtual file object with plaintext-pak semantics.

That means:

1. The game never receives the real `.mhwsmod` file handle.
2. All file-state APIs for the virtual pak are answered from our own state.
3. Externally visible file size, pointer movement, random reads, and completion state all correspond to the decrypted plaintext pak view.
4. Container metadata remains internal only; game offsets must always be interpreted against plaintext pak coordinates.

## Required Properties

### 1. Synthetic handle only

For virtual encrypted pak targets, always return a synthetic handle.
Do not expose the real encrypted backing handle to the game.

### 2. Plaintext file-size semantics

`GetFileSizeEx` and related file-information APIs must report plaintext pak size, not encrypted container size.

### 3. Plaintext random-read semantics

For any `offset + size`, resolve the affected plaintext chunks, read only the needed encrypted chunk records, decrypt them independently, and copy the requested plaintext window.

### 4. No full plaintext pak requirement

We do not need to keep the full decrypted pak resident in memory.
What must remain resident is:

- header/metadata
- chunk map / per-chunk addressing info
- keys / nonces needed for chunk-level decryption
- small hot-cache of decrypted chunks
- per-request staging buffers

### 5. Minimize issue-time visibility differences

Do not let the game observe completion too early.
Do not rely on heuristic issue-time publication rules unless verified against plaintext behavior.

## First Refactor Direction

The next practical refactor should focus on these changes first:

1. Force synthetic handles for virtual encrypted pak opens.
2. Stop syncing backing file pointers for the virtual pak path.
3. Treat virtual pak state as the sole source of truth for file size and current position.
4. Keep file-state APIs consistent with the synthetic plaintext view.
5. Only then re-check whether the encrypted run's initial async request order moves closer to the plaintext baseline.

## Implementation Checkpoint

As of 2026-03-26, the first synthetic-only refactor pass has been implemented in code.

Applied changes:

1. Virtual encrypted pak opens no longer open and return the real encrypted source handle.
   `try_open_virtual_pak(...)` now materializes the virtual source metadata/payload and immediately returns a synthetic virtual file handle.

2. `create_virtual_file_handle(...)` now always allocates a synthetic file handle for the virtual pak path.
   The real `.mhwsmod` backing handle is no longer exposed to the game through this route.

3. Virtual file-state APIs were collapsed onto synthetic state.
   `SetFilePointerEx`, `GetFileType`, `GetFileInformationByHandle`, `GetFileInformationByHandleEx`, and `NtQueryInformationFile` now answer the virtual pak view directly instead of trying to preserve mixed real-handle behavior.

4. Synthetic-handle lifecycle gaps were closed.
   `DuplicateHandle`, `ReOpenFile`, `CloseHandle`, and `GetFinalPathNameByHandleW` now have virtual-handle behavior for the pure synthetic route.

5. Synthetic async completion semantics were tightened.
   `ReadFileEx` no longer publishes staged bytes at issue time.
   `NtReadFile` no longer publishes staged bytes or success-looking `IO_STATUS_BLOCK` state at issue time.
   The synthetic `NtReadFile` path now allows queued async completion when either APC delivery or event-based completion is requested.

6. `GetOverlappedResult` now has a synthetic virtual-handle path.
   This avoids immediately falling back to the real Win32 API with a fake handle value if the game queries completion state through the overlapped result API.

7. The repository still does not keep the full plaintext pak permanently resident by design.
   The random-access chunked view remains the intended long-term backend; this pass changed file-object semantics, not the payload strategy.

Build status:

- `cmake --build build --config Release` completed successfully on 2026-03-26.
- Output DLL: `build\\Release\\version.dll`

Highest remaining risk after this pass:

1. Even with the real backing handle removed, our completion timing is still synthetic worker/APC driven rather than true kernel file-object behavior.
2. If the encrypted run still diverges from the plaintext baseline, the next investigation should focus on async completion visibility/order rather than chunk math.

## DirectStorage Follow-up

On 2026-03-26, runtime logs showed the synthetic handle could survive `GetFileSizeEx` and the first two bootstrap `ReadFile` calls, then get closed by the game. The more important bug was that the DirectStorage rewrite path still pointed later pak activity back at the raw `.mhwsmod` source in pure-memory mode.

Specifically:

1. `same_point_directstorage_hook(...)` rewrote the requested patch pak path to `resolve_redirect_source_for_requested_path(...)`.
2. `hooked_directstorage_open(...)` also rewrote virtual pak requests to `current_virtual_source_path()`.
3. In `rf_chain_mode` with `stage_source=0`, `ensure_runtime_source_path_prepared()` returns the original encrypted `.mhwsmod` path.

That means pure-memory mode was still leaking the encrypted container path into later DirectStorage-facing logic even after the synthetic handle refactor. The next corrective step is to defer those DirectStorage rewrites whenever the rf-chain source is still an encrypted `.mhwsmod`, instead of blindly redirecting to the raw source path.

## Important Constraint

Do not use hardware breakpoints during normal iteration here.
They are known to crash this game and are only acceptable for rare critical captures.

## What To Read In Code First

- `src/plugin/40_matching_and_tracking.cpp`
- `src/plugin/50_virtual_fs_and_hooks.cpp`
- `src/plugin/30_config_and_crypto.cpp`
- `src/plugin/plugin_internal.hpp`

## Expected Validation After Refactor

After the synthetic-handle refactor, compare encrypted-vs-plaintext logs again and check:

1. Does the encrypted run still start with the divergent first async read at `0x2e0`?
2. Do later synchronous/random offsets move closer to the plaintext baseline?
3. Are there still issue-time visible state differences for pending async reads?

If the first async sequence is still divergent after the synthetic-handle cutover, the next focus should be async completion semantics rather than payload math.
