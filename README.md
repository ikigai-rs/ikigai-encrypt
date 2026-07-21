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
`urn:secret:*`). **This crate never mints keys** — generating and storing them is the
secret module's job, exactly as `ikigai-sign` leaves keygen to the secret module.

## Using it from a host

```rust,ignore
let space = ikigai_encrypt::space(); // binds urn:encrypt:encrypt + urn:encrypt:decrypt
// mount into your kernel alongside the other modules
```

Native-focused: the `age` stack runs on the edge and the owner's devices (encrypt on the
edge, decrypt on your laptops), not in the browser — so there is no wasm face.

## License

MIT OR Apache-2.0
