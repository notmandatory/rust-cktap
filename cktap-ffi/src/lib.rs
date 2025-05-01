#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub use rust_cktap::{
    rand_chaincode, rand_nonce as core_rand_nonce, CkTapCard, Error, SatsCard, TapSigner,
};

#[cfg(feature = "uniffi")]
#[derive(uniffi::Object)]
pub struct TestStruct {
    pub value: u32,
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
pub fn rand_nonce() -> Vec<u8> {
    core_rand_nonce().to_vec()
}
