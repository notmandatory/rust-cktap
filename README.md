# rust-cktap

A Rust implementation of the Coinkite Tap Protocol for use with [SATSCARD]™ and [TAPSIGNER]™ products.

### Desktop Example

#### Prerequisites

1. USB PCSC NFC card reader, for example:  
   * [Advanced Card Systems Ltd. ACR1252](https://www.acs.com.hk/en/products/342/acr1252u-usb-nfc-reader-iii-nfc-forum-certified-reader/)
2. Coinkite SATSCARD™ and TAPSIGNER™ cards

#### Run steps

1. Install vendor PCSC driver
2. Connect NFC reader to desktop system
3. Place SATSCARD or TAPSIGNER on reader
4. Run example
   ```
   cargo run --example pcsc --features pcsc
   ```

[SATSCARD]: https://satscard.com/
[TAPSIGNER]: https://tapsigner.com/