#[uniffi::export]
fn rand_nonce() -> Vec<u8> {
    crate::rand_nonce().to_vec()
}
