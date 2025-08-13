# rust-cktap

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/notmandatory/rust-cktap/blob/master/LICENSE)
[![CI](https://github.com/notmandatory/rust-cktap/actions/workflows/test.yml/badge.svg)](https://github.com/notmandatory/rust-cktap/actions/workflows/test.yml)
[![Audit](https://github.com/notmandatory/rust-cktap/actions/workflows/audit.yml/badge.svg)](https://github.com/notmandatory/rust-cktap/actions/workflows/audit.yml)
[![rustc](https://img.shields.io/badge/rustc-1.81.0%2B-lightgrey.svg)](https://blog.rust-lang.org/2024/09/05/Rust-1.81.0/)

A Rust implementation of the [Coinkite Tap Protocol](https://github.com/coinkite/coinkite-tap-proto) (cktap)
for use with [SATSCARD], [TAPSIGNER], and [SATSCHIP] products.

This project provides PC/SC APDU message encoding and decoding, cvc authentication, certificate chain verification, and card response verification.

It is up to the crate user to send and receive the raw cktap APDU messages via NFC to the card by implementing the `CkTransport` trait. An example implementation is provided using the optional rust `pcsc` crate. Mobile users are expected to implement `CkTransport` using the iOS or Android provided libraries.

### Supported Features

- [x] [IOS Applet Select](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#first-step-iso-applet-select)
- [x] [CVC Authentication](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#authenticating-commands-with-cvc)

#### Shared Commands

- [x] [status](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#status)
- [x] [read](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#status) (messages)
  - [x] response verification
- [x] [derive](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#derive) (messages)
  - [x] response verification
- [x] [certs](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#certs)
- [x] [new](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#new)
- [x] [nfc](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#nfc)
- [x] [sign](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#sign) (messages)
  - [ ] response verification
- [x] [wait](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#wait)

#### SATSCARD-Only Commands

- [x] [unseal](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#unseal)
- [x] [dump](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#dump)

#### TAPSIGNER-Only Commands

- [x] [change](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#change)
- [x] [xpub](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#xpub)
- [x] [backup](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#backup)

### Automated Testing with Emulator

1. Install dependencies for [cktap emulator](https://github.com/coinkite/coinkite-tap-proto/blob/master/emulator/README.md)
2. run tests with emulator: `just test`

### Manual Testing with real cards

#### Prerequisites

1. USB PCSC NFC card reader, for example:
   - [OMNIKEY 5022 CL](https://www.hidglobal.com/products/omnikey-5022-reader)
2. Coinkite SATSCARD, TAPSIGNER, or SATSCHIP cards
   Install vendor PCSC driver
3. Connect NFC reader to desktop system
4. Place SATSCARD, TAPSIGNER, or SATSCHIP on reader

#### Run CLI

```
cargo run -p cktap-cli -- --help
cargo run -p cktap-cli -- certs
cargo run -p cktap-cli -- read
```

## Minimum Supported Rust Version (MSRV)

This library should always compile with any valid combination of features on Rust **1.81.0**.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[SATSCARD]: https://satscard.com/
[TAPSIGNER]: https://tapsigner.com/
[SATSCHIP]: https://satschip.com/
