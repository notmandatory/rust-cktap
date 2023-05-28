# rust-cktap

A Rust implementation of the [Coinkite Tap Protocol](https://github.com/coinkite/coinkite-tap-proto) 
for use with [SATSCARD], [TAPSIGNER], and [SATSCHIP] products.

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

[SATSCARD]: https://satscard.com/
[TAPSIGNER]: https://tapsigner.com/
[SATSCHIP]: https://satschip.com/