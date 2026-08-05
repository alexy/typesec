# DID Envelope Authentication V2

This document is the canonical binary-transcript contract for
`authVersion: "typesec.did-envelope-auth.v2"`. A gateway accepts only that
exact value. Missing, legacy, and unknown versions fail closed; changing the
field set or encoding requires a new authentication version.

## Primitive Encoding

Every transcript is a sequence of named fields. Define:

```text
frame(bytes)       = u64_be(bytes.length) || bytes
field(name, value) = frame(utf8(name)) || frame(value)
```

Strings are UTF-8 bytes without normalization. Unsigned integers and counts are
eight-byte big-endian values. Booleans are one byte (`0x00` or `0x01`). Optional
objects always include their presence boolean before any conditional fields.
Nested transcripts are included as one byte-valued field, including all of the
nested transcript's framing.

Recipient order is preserved. Claims are encoded in ascending
`BTreeMap<String, String>` key order, which is lexicographic UTF-8 order, and
are preceded by a count. Field names and values are both framed, so delimiters
inside strings cannot create the same transcript as a different field layout.

## Authenticated Header

The header starts with
`field("domain", "typesec.did-envelope-auth.v2/header")`, followed by these
fields in order:

```text
authVersion
id
messageType
from
recipientCount
recipient (repeated recipientCount times)
createdTime
expiresTime
action
resource
privacy
claimCount
claimName, claimValue (repeated claimCount times)
hasReplyTo
replyToId, replyToDigest (only when hasReplyTo is true)
hasTypeDid
conversationId, deliveryMode, profile, protocol,
hasConversationExpiry, conversationExpiresAt (only when present)
  (the conversation fields occur only when hasTypeDid is true)
kid
nonce
```

`deliveryMode` is either `send` or `request_reply`. The nonce and all other hex
wire values are authenticated as their wire strings. The complete header bytes
are the AEAD associated data.

## Signature Transcript

The signature transcript starts with
`field("domain", "typesec.did-envelope-auth.v2/signature")`, then contains:

```text
authenticatedHeader = complete authenticated-header bytes
ciphertext           = UTF-8 ciphertext wire string
```

The sender signs these complete bytes, and the gateway verifies the same bytes.

After signature verification, gateways enforce the authenticated
`messageType` before key agreement, decryption, or replay-store consumption:

- `DidMessageGateway` accepts only the prompt and reply message-type URIs.
- `TypeDidGateway` accepts only the TypeDID message-type URI and requires
  TypeDID conversation metadata.

A validly signed envelope sent to the wrong gateway fails with a typed
`DidError::UnexpectedMessageType`; it is not silently reinterpreted as another
protocol.

## Reference Transcript

The reference transcript starts with
`field("domain", "typesec.did-envelope-auth.v2/reference")`, then contains:

```text
signedEnvelope = complete signature-transcript bytes
signature      = UTF-8 signature wire string
```

`DidEnvelope::reference().digest` is:

```text
"sha256:" || lowercase_hex(SHA-256(reference_transcript))
```

The deterministic fixture at
[`crates/typesec-integrations/tests/fixtures/did-envelope-auth-v2.json`](../crates/typesec-integrations/tests/fixtures/did-envelope-auth-v2.json)
pins the authenticated-header digest, signature-transcript digest, and final
reference for parity testing in other languages.

## Expiry and Verified Provenance

For TypeDID messages, the effective expiry is the minimum of the outer
`expires_time` and an optional conversation `expires_at`. Gateways reject an
effective expiry at or before the current time. Successful verification returns
private-field provenance types with read-only accessors; callers cannot
construct a `VerifiedDidPrompt` or `VerifiedTypeDidMessage` from unverified
metadata.
