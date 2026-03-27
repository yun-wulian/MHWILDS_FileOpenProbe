# Encryption Flow Design

## Current Goal

The current experimental goal is to recover a pure-memory pak path that can survive the game's long-lived pak handles and arbitrary offset reads.

The accepted near-term goal is:

- keep the existing staged plaintext path as a fallback
- switch the encrypted pak payload layout to chunked random-access form
- make the container readable at arbitrary plaintext offsets without full-file buffering
- preserve the existing encrypted metadata block so update gating stays compatible
- reuse the same chunk mapping later for native stream hooks

## Hard Constraints

- The decrypt / staging step must block custom pak exposure.
- We must not let the game finish pak enumeration before staged files exist.
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

Multi-threaded decrypt / staging is still the preferred optimization path, but it is a second step.

The immediate priority is:

1. complete the `v2` container
2. make single-process decrypt / verify correct
3. keep the startup path blocking

After that, we can parallelize independent `.mhwsmod` files while still waiting for all staging work to finish before the custom pak chain is exposed.

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
