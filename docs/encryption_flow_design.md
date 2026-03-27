# Encryption Flow Design

## Current Status

`main` now has a validated pure-memory encrypted pak route for chunked `v2` `.mhwsmod` packages.

The currently proven backend is the WinAPI virtual-handle path: the game receives a virtualized file object while the loader decrypts requested plaintext slices on demand from the encrypted container. This keeps plaintext off disk and avoids holding the whole plaintext pak in memory for chunked payloads.

The accepted direction is now:

- keep the existing staged plaintext path only as fallback infrastructure
- use chunked random-access encrypted payloads as the primary format for encrypted pak delivery
- make the container readable at arbitrary plaintext offsets without full-file buffering
- preserve the existing encrypted metadata block so update gating stays compatible
- keep native game stream hooks as analysis / future-hardening targets, not as the current serving path

## Hard Constraints

- The virtual handle and slice context must be ready before custom pak exposure.
- We must not let the game finish pak enumeration before the encrypted packages can answer size / seek / read queries.
- Real user setups may include several GB of mod data.
- Startup performance matters, so the format and loader must be stream-friendly.
- We should reuse the same encrypted container design for future temp-index storage.

## Accepted Direction

### Format Versioning

The old prototype format remains supported as legacy `v1`:

- magic: `MHWSEP1`
- algorithms:
  - `1`: AES-256-CBC without authentication
  - `2`: XOR prototype

The new default format is `v2`:

- magic: `MHWSEP2`
- algorithms:
  - `3`: AES-256-CBC + HMAC-SHA256
  - `4`: chunked AES-256-CBC + per-chunk HMAC-SHA256
- explicit `purpose`
  - `1`: pak payload
  - `2`: encrypted temp-index payload
  - `3`: encrypted metadata payload

### Why `v2`

The new container must let the loader distinguish:

- unsupported format version
- unsupported algorithm
- game build mismatch
- damaged file / wrong key / authentication failure

That means decrypt failure alone is not a sufficient diagnostic.

## Key Derivation

The loader computes `MD5(MonsterHunterWilds.exe)` once per launch and treats it as the game fingerprint.

The MD5 is not used directly as the AES key. It is only the root material for key derivation.

Per-purpose keys are derived from the fingerprint:

- encryption key: `SHA256("mhwsmod-v2|enc|" + purpose + fingerprint)`
- authentication key: `SHA256("mhwsmod-v2|mac|" + purpose + fingerprint)`

This keeps pak payloads and future index payloads separated even though they share the same game fingerprint source.

## `v2` Container Fields

The `v2` header contains:

- `magic`
- `version`
- `header_size`
- `algorithm`
- `purpose`
- `plain_size`
- `cipher_size`
- `game_fingerprint`
- `iv`
- `auth_tag`

For algorithm `3`, `auth_tag` is `HMAC-SHA256` over the plaintext payload.

For algorithm `4`, the layout is:

- `HeaderV2`
- encrypted metadata container
- per-chunk auth table
- chunked pak ciphertext

In chunked mode:

- `header.reserved[0..15]` stores flags, metadata container size, plain chunk size, and per-chunk auth tag size
- `header.auth_tag` becomes a container-level HMAC over `zeroed-header-auth_tag + auth_table`
- each auth-table entry stores `HMAC-SHA256` over one plaintext chunk
- payload chunk `i` is addressed by plaintext chunk index, so arbitrary offset reads can be mapped without sequential state

This choice keeps runtime decrypt simple for staged fallback and also gives the native path a stable random-access mapping:

- one pass over the ciphertext
- decrypt chunk by chunk
- update HMAC on the decrypted plaintext
- delete the staged output if the final tag does not match

## Runtime Flow

For each `.mhwsmod` file:

1. Read and validate the container header.
2. Compare the stored game fingerprint with the current exe MD5.
3. Derive purpose-specific keys.
4. Either decrypt to a randomized temp `.pak` path or serve chunk slices directly from the encrypted source.
5. Verify the final HMAC.
6. Only append the staged `.pak` path to the rf-chain list after verification succeeds.

This path is synchronous by design.

## Performance Direction

The current prototype was acceptable for tiny mods, but it used an inefficient model:

- read full encrypted file
- decrypt into a second full buffer
- write the full plaintext file

That does not scale to several GB of mods.

The new baseline should be:

- streaming file IO
- bounded chunk buffers
- sequential writes
- no full-file duplicate buffers

Recommended defaults:

- IO chunk size: `8 MiB`
- startup remains blocking
- per-file decryption logic is stream-oriented

## Multi-Threading

Multi-threaded slice preparation / verification is still an optimization path, but it is no longer the blocker for encrypted pak loading.

The current working priority is:

1. keep the `v2` random-slice path correct under arbitrary offset reads
2. harden the virtual-handle query / mapping surface where the game may ask for more file semantics
3. reduce open-time overhead without reintroducing plaintext staging

After that, we can parallelize independent `.mhwsmod` preparation and concurrent slice servicing where it materially improves startup or streaming latency.

## Error Model

The loader should report these cases separately:

- unsupported container version
- unsupported algorithm
- header size / payload size mismatch
- game fingerprint mismatch
- decrypt failure
- authentication failure

The user-facing implication is:

- unsupported version / algorithm: update the DLL
- fingerprint mismatch: the mod was packed for another game build
- auth failure: file damage, wrong key material, or implementation error

## Near-Term Work

- implement chunked `v2` pak payload support end to end
- switch the packer to emit authenticated chunked `v2` files by default
- keep `v1` read compatibility during transition
- keep the staged path working while native stream hooks are still incomplete
- later reuse the same format for the encrypted temp-index file
