# Dotnet Packer Design

## Goal

Build a standalone .NET packer for mod creators that can produce our encrypted
`.mhwsmod` packages from ordinary RE Engine loose-file mod folders.

The packer should own the full authoring pipeline:

1. collect loose files from a mod folder
2. build a plain RE Engine `.pak`
3. encrypt that pak into our `mhwsmod` container
4. optionally embed mod metadata for future per-mod update checks

This tool is for packaging, not runtime loading.

## Reference Project Findings

Reference repository:

- `external/ree-pak-rs`
- commit: `a2ab23c462d3ef0706f5c5f719ec2eaaaeb7fbdb`

Relevant implementation points:

- `ree-pak-cli/src/pack.rs`
- `ree-pak-core/src/write/mod.rs`
- `ree-pak-core/src/utf16_hash.rs`
- `ree-pak-core/src/pak/header.rs`
- `ree-pak-core/src/pak/entry.rs`

Confirmed behavior from `ree-pak-rs`:

1. It recursively collects files from an input directory.
2. It preserves the internal directory structure starting at `natives/`.
3. It writes RE pak header `KPKA`, version `4.0`.
4. It stores only the mixed UTF-16 file path hash in the entry table.
5. The mixed hash is:
   - upper 32 bits: Murmur3 over UTF-16LE upper-case path
   - lower 32 bits: Murmur3 over UTF-16LE lower-case path
   - current implementation uses ASCII-only case conversion optimization
6. The writer currently emits plain payload bytes:
   - no native pak compression
   - no native pak entry encryption
   - no chunk table
   - no extra feature flags

That subset is enough for our current loader flow because we already verified
that the game accepts plain staged pak files produced by our chain.

## What We Should Reuse Conceptually

We do not need to reuse Rust code directly.

What we should reuse is the packaging model:

- loose files in
- trim path before `natives/`
- normalize to forward-slash logical paths
- compute RE pak path hashes
- write a deterministic `KPKA` v4.0 pak with plain entries

This is small enough to port cleanly to C# without dragging Rust into the
creator workflow.

## Proposed Tool Scope

Initial scope for the .NET packer:

1. `folder -> pak`
2. `pak -> mhwsmod`
3. `folder -> mhwsmod` as the main author-facing command

Non-goals for first iteration:

- unpack GUI
- native pak compression
- native pak entry encryption
- chunk-table pak variants
- automatic game install discovery
- patch merging / diff building

## Proposed Target Framework

Use `.NET 8` for the packer project.

Reasons:

- stable LTS target
- available on this machine
- easy single-file publish for creators
- broad Windows compatibility

The SDK on this machine is newer, but the output target should stay `net8.0`.

## Proposed Project Layout

Create a separate .NET solution under this repository, for example:

- `dotnet/MHWILDS.ModPackager.Core/`
- `dotnet/MHWILDS.ModPackager.Cli/`

Suggested responsibilities:

### `MHWILDS.ModPackager.Core`

- file discovery
- path normalization
- RE pak hash implementation
- pak writer
- `mhwsmod` container writer
- metadata serialization

### `MHWILDS.ModPackager.Cli`

- command-line parsing
- human-readable validation errors
- progress output
- drag-and-drop friendly entry mode later if needed

## Proposed Commands

### Main command

`pack`

Primary usage:

```powershell
MHWILDS.ModPackager.Cli.exe pack ^
  --game-exe "E:\SteamLibrary\steamapps\common\MonsterHunterWilds\MonsterHunterWilds.exe" ^
  --input "D:\Mods\MyMod" ^
  --output "D:\Build\MyMod.mhwsmod"
```

### Optional helper commands

`build-pak`

- builds a plain pak only
- useful for debugging and compatibility comparison

`encrypt-pak`

- converts an existing pak into `.mhwsmod`
- useful when creators already have another pak workflow

`inspect`

- reads `mhwsmod` header + metadata without full decryption
- useful for support and update troubleshooting

## Input Model

The packer should accept either:

1. a loose-file directory
2. an existing `.pak`

For loose-file directories:

- recursively scan files
- normalize Windows separators to `/`
- find `natives/` in the logical path
- trim everything before `natives/`
- reject empty file sets

If `natives/` is missing:

- fail by default with a clear error
- optionally allow an explicit override later, such as `--logical-root`

Failing hard is better than silently producing unusable packages.

## Pak Writer Rules

The first implementation should deliberately stay minimal and deterministic:

- header magic: `KPKA`
- version: `4.0`
- feature flags: `0`
- payloads written as-is
- entry count exactly matches the collected file count
- sort entries by normalized logical path before writing

Sorting is important so repeated builds produce stable pak structure when the
input set is unchanged.

## Hashing Rules

Implement the same mixed hash model used by `ree-pak-rs`:

1. UTF-16LE encode the normalized logical path
2. build lower-case hash stream
3. build upper-case hash stream
4. Murmur3 32-bit with seed `0xFFFFFFFF`
5. combine as `(upper << 32) | lower`

For the first version, ASCII-only case mapping is acceptable because RE asset
paths are effectively ASCII in practice. That keeps the implementation simple
and aligned with the reference project.

## `mhwsmod` Container Integration

After the plain pak is built, wrap it into our existing container:

- version: current `v2`
- algorithm: AES-256-CBC + HMAC-SHA256
- purpose: pak
- game fingerprint: `MD5(MonsterHunterWilds.exe)`

The .NET implementation must match the current DLL and native packer exactly:

- same MD5 source
- same key derivation labels
- same IV size
- same AES mode
- same HMAC computation model

That keeps the generated packages compatible with the current loader without
changing runtime code first.

## Metadata Extension Plan

We should start reserving per-mod metadata now.

Important observation:

- our `HeaderV2` already contains `header_size`
- the loader already accepts `header_size > sizeof(HeaderV2)`
- runtime decryption already starts payload reading from `header_size`

That means we can append an optional metadata block after `HeaderV2` without
immediately changing the container version.

### Proposed metadata block

Store a small UTF-8 JSON blob in the extended header area.

Suggested fields:

- `schema_version`
- `mod_id`
- `display_name`
- `author`
- `mod_version`
- `update_post_url`
- `homepage_url`
- `description`
- `build_time_utc`
- `tool_version`

This is enough for later per-mod update checks and support diagnostics.

### Important note

In the current `v2` design, HMAC authenticates the plaintext pak payload, not
the extended metadata block.

That is acceptable for the next step because the metadata is advisory, not a
security boundary. If we later need authenticated metadata, we can either:

1. include metadata bytes in the MAC input, or
2. introduce a `v3` container

For now, do not block implementation on this.

## Recommended Build Pipeline

For `folder -> mhwsmod`:

1. scan loose files
2. validate and normalize logical paths
3. build a temporary plain pak stream
4. encrypt into final `.mhwsmod`
5. write optional metadata block into the extended header
6. optionally emit the plain pak if `--emit-pak` is requested

Prefer streaming where practical, but it is acceptable for the first version to:

- build the pak into a temp file
- then encrypt that temp file

The runtime path is performance-critical.
The creator-side packer is much less sensitive, so implementation clarity wins.

## Validation Strategy

We should validate the .NET packer in layers:

1. hash parity tests against known sample paths
2. pak structure tests against small synthetic folders
3. compare output pak metadata with `ree-pak-rs` on the same input set
4. wrap into `.mhwsmod`
5. load through the current DLL in game

Recommended golden tests:

- a folder with one file under `natives/...`
- a folder with multiple nested files
- path case variations
- a folder missing `natives/` to verify hard-fail behavior

## Practical Recommendation

Implement the .NET packer in two phases.

### Phase 1

- `build-pak`
- `encrypt-pak`
- `pack`
- metadata block writing
- tests for hash and pak structure

### Phase 2

- `inspect`
- drag-and-drop mode
- optional GUI shell if creators need it
- per-mod update metadata consumption on the DLL side

## Why This Is The Right Next Step

Right now our native packer only handles:

- existing pak in
- encrypted `mhwsmod` out

That is not enough for creators.

The missing product layer is not encryption anymore. It is authoring:

- take an ordinary mod folder
- convert it into a valid RE pak
- then wrap it into our container with future update metadata

That is exactly the gap this .NET packer should fill.
