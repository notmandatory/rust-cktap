# rust-cktap

A Rust implementation of the [Coinkite Tap Protocol](https://github.com/coinkite/coinkite-tap-proto) (cktap)
for use with [SATSCARD], [TAPSIGNER], and [SATSCHIP] products.

This project provides PC/SC APDU message encoding and decoding, cvc authentication, certificate chain verification, and card response verification. 

It is up to the crate user to send and receive the raw cktap APDU messages via NFC to the card by implementing the `Transport` trait. An example implementation is provided using the optional rust `pcsc` crate. Mobile users are expected to implement `Transport` using the iOS or Android provided libraries.

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

- [ ] [change](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#change)
- [x] [xpub](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#xpub)
- [ ] [backup](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#backup)

### Desktop Example

#### Prerequisites

1. USB PCSC NFC card reader, for example:  
   * [OMNIKEY 5022 CL](https://www.hidglobal.com/products/omnikey-5022-reader)
3. Coinkite SATSCARD, TAPSIGNER, or SATSCHIP cards

#### Run steps

1. Install vendor PCSC driver
2. Connect NFC reader to desktop system
3. Place SATSCARD, TAPSIGNER, or SATSCHIP on reader
4. Run example
   ```
   cargo run --example pcsc --features pcsc
   ```
   **TODO: create CLI tool to replace example**

[SATSCARD]: https://satscard.com/
[TAPSIGNER]: https://tapsigner.com/
[SATSCHIP]: https://satschip.com/