# rust-cktap

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/notmandatory/rust-cktap/blob/master/LICENSE)
[![CI](https://github.com/notmandatory/rust-cktap/actions/workflows/test.yml/badge.svg)](https://github.com/notmandatory/rust-cktap/actions/workflows/test.yml)
[![rustc](https://img.shields.io/badge/rustc-1.57.0%2B-lightgrey.svg)](https://blog.rust-lang.org/2021/12/02/Rust-1.57.0.html)

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
  - [ ] response verification
- [x] [derive](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#derive) (messages)
  - [ ] response verification
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
- [ ] [backup](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#backup)

### Automated Testing with Emulator

1. Install and start [cktap emulator](https://github.com/coinkite/coinkite-tap-proto/blob/master/emulator/README.md)
   - TapSigner: `./ecard.py emulate -t --no-init`
   - SatsCard: `./ecard.py emulate -s`
2. run tests: `cargo test --features emulator`

### Manual Testing with real cards

#### Prerequisites

1. USB PCSC NFC card reader, for example:
   * [OMNIKEY 5022 CL](https://www.hidglobal.com/products/omnikey-5022-reader)
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

[SATSCARD]: https://satscard.com/
[TAPSIGNER]: https://tapsigner.com/
[SATSCHIP]: https://satschip.com/
