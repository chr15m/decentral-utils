A minimal set of JavaScript utility functions for decentralized web applications.

`npm i decentral-utils`

## Encoding and decoding from `Uint8Array`s

### `u8_to_hex(uint8_array)`

Turns a `Uint8Array` of bytes into a hex string e.g. `Uint8Array([222, 173, 190, 239, 192, 222])` becomes `"deadbeefc0de"`. Will also work with ordinary arrays containing byte values between 0 and 255.

### `hex_to_u8(hex_string)`

Turns a hex string into a `Uint8Array` of bytes e.g. `"0xdeadbeefc0de"` becomes `Uint8Array([222, 173, 190, 239, 192, 222])`. The `0x` prefix is not required and is ignored.

### `utf8_to_u8(utf8_string)`

Turns a utf8 encoded string into a `Uint8Array` of bytes e.g. `"Hello! 中英字典"` becomes `Uint8Array([72,101,108,108,111,33,32,228,184,173,232,139,177,229,173,151,229,133,184])`.

Uses `TextDecoder("utf8")` in the Browser and `Buffer(...).toString("utf8)` in node.

### `u8_to_utf8(uint8_array)`

Turns a `Uint8Array` of bytes into a utf8 encoded string e.g. `Uint8Array([72,101,108,108,111,33,32,228,184,173,232,139,177,229,173,151,229,133,184])` becomes `"Hello! 中英字典"`.

Uses `TextEncoder("utf8")` in the Browser and `Buffer(...).toString("utf8)` in node.

## Implementation of BEP44 semantics

[BEP44](http://bittorrent.org/beps/bep_0044.html) describes a technique for ensuring clients have the latest copy of some mutable data specified by some identity, where identities are key pairs (similar to SSH). In BEP44 they are Ed25519 keypairs but this function is agnostic about the signing and verification algorithm / implementation used. BEP44 was intended for implementation in the BitTorrent Mainline DHT but this library abstracts it so that it can be used more widely in decentralized systems.

The basic BEP44 datastructure is as follows:

```
"v": <the mutable data (Uint8Array of length < 1000)>
"seq": <monotonically increasing sequence number (integer)>,
"cas": <[optional] expected seq number (integer)>,
"salt": <[optional] salt (string, works like a namespace per pubkey)>
"k": <ed25519 public key (Uint8Array of length 32)>,
"sig": <ed25519 signature (Uint8Array of length 64)>,
```

In BEP44 the `v` field is supposed to be bencoded but most implementations, including this one, do not check for this.

The optional `salt` field allows for namespacing so that you can have more than one piece of data for a particular public key, keyed on the salt field.

The required `seq` field offers protection against replay attacks as it should be monotonically increasing.

The `cas` field offers basic [compare-and-swap](https://en.m.wikipedia.org/wiki/Compare-and-swap) functionality such that a datastructure will only be considered the canonical version if the `cas` field matches the previous version's `seq` field.

## `make_struct(fields)`

Create the required datastructure for passing around locally or over the network to the verification functions.

Examples:

 * `make_struct({"v": 12})`
 * `make_struct({"v": "hello", "seq": 15})`
 * `make_struct({"v": "hello", "salt": "beep", "seq": 15})`
 * `make_struct({"v": "hello", "salt": "beep", "seq": 15, "cas": 14})`

## `freshest(struct, struct_new, verify)`

Check which of `struct` and `struct_new` is the latest valid version and return it.

The `verify` function signature should match that of [nacl.sign.detached.verify](https://github.com/dchest/tweetnacl-js#naclsigndetachedverifymessage-signature-publickey) i.e. `verify(message, signature, publicKey)` where all values are `Uint8Array`s.

## `make_sig_check(fields)`

Returns the string required for signing and signature checks from the `.v` and `.salt` and `.seq` fields in bencoded format.
