# ikigai-encrypt

Public-key encryption as an [ikigai](https://github.com/ikigai-rs) module — the
**dual of [`ikigai-sign`](https://github.com/ikigai-rs/ikigai-sign)**. Signing proves
*who*; encryption hides *what*. Two endpoints over the
[`age`](https://age-encryption.org) format (X25519 recipients, ChaCha20-Poly1305,
ASCII armor):

```text
# seal to a recipient's public key (OPEN — anyone may encrypt to a public key)
source urn:file:msg.txt | urn:encrypt:encrypt to=urn:secret:brian.pub   # -> armored age

# open it with the owner's identity (requires urn:cap:decrypt)
source urn:file:msg.age | urn:encrypt:decrypt key=urn:secret:brian      # -> plaintext
```

## Why it's the dual of signing

`ikigai-sign` turns bytes + a key into a signature you can verify; `ikigai-encrypt`
turns bytes + a **recipient public key** into ciphertext only the holder of the
**identity** can open. Together they're the two halves of a message you can trust *and*
keep private — sign-then-encrypt: the sender signs (provenance), then encrypts to the
recipient (confidentiality); the recipient decrypts, then verifies.

## Capability model

- **`urn:encrypt:encrypt` is open.** Encrypting to a public key needs no secret, so it
  needs no capability — which is exactly the "untrusted dropper seals a request to an
  inbox owner" case.
- **`urn:encrypt:decrypt` requires `urn:cap:decrypt`.** It wields the private key. A
  wrong key or a tampered ciphertext is a typed `Denied`/error, never a panic.

## Multi-recipient (the inbox-across-devices case)

The `to` resource may list **several `age1…` recipients, one per line**. A message
encrypted to all of an owner's device keys can be opened by **any one** of them — so an
inbox hosted at a public edge can be sealed to your laptop *and* your desktop *and* your
phone, and you review it from wherever you are, while the edge only ever holds
ciphertext.

## Keys

Keys are `age` recipients (`age1…`) and identities (`AGE-SECRET-KEY-1…`), resolved
**through the kernel** (`to=`/`key=` are resource URIs — a `urn:file:` or a
`urn:secret:*` — never the key by value; an error never echoes what it was given). **This crate never mints keys** — generating and storing them is the
secret module's job, exactly as `ikigai-sign` leaves keygen to the secret module.

## Caching

- **`urn:encrypt:encrypt` is never cacheable.** age mints a fresh ephemeral key per
  call, so two sealings of one plaintext to one recipient are different bytes; a
  cached ciphertext would be a function of nothing. Every encrypt is `Expiry::Always`.
- **`urn:encrypt:decrypt` is exactly as cacheable as its key.** A pure function of the
  ciphertext and the identity, marked cacheable, holding no key material and naming
  no thread of its own — the kernel folds the `key` resource's expiry and golden
  threads into the plaintext. Serve the identity under a thread (an `ikigai-fs`
  cacheable mount, `urn:file:`) and the plaintext is cached under that thread; serve
  it uncacheable (a secret backend read on every call, `urn:secret:*`) and every
  decryption recomputes. The cache keys on the capability fingerprint, so a caller
  without `urn:cap:decrypt` never sees a cached plaintext.
- **A cached plaintext outlives a key rotation until the cut.** This crate watches
  nothing: after the operator rotates an identity that was served under a thread, the
  plaintext opened with the OLD key is served from the cache — and the rotated key is
  not even read — until the keystore cuts the thread it declared (the key's own IRI).
  A `urn:secret:*` identity never has this window (it is live); a `urn:file:` one does,
  and closing it is the filesystem watcher's job, not this module's.

## Conformance

Passes [`ikigai-conformance`](https://github.com/ikigai-rs/ikigai-conformance)
(`tests/conformance.rs`): every check, no opt-outs, over both keystore kinds. Pinned
by hand beyond the suite: every encrypt is live (and declaring it cacheable draws the
finding), the rotation window above, a missing `in`/`to`/`key` is a typed
`MissingArgument` before any key is read, an ungranted caller is refused before the
identity is consulted, and no face — description, catalog, action manifold, `Meta`,
or any error text a caller can provoke (including passing the identity itself as
`key=`) — carries the private key.

## Using it from a host

```rust,ignore
let space = ikigai_encrypt::space(); // binds urn:encrypt:encrypt + urn:encrypt:decrypt
// mount into your kernel alongside the other modules
```

Native-focused: the `age` stack runs on the edge and the owner's devices (encrypt on the
edge, decrypt on your laptops), not in the browser — so there is no wasm face.

## License

MIT OR Apache-2.0
