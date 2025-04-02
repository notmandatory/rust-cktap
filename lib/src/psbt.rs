use crate::tap_signer::PsbtSignError;
use bitcoin::Psbt;

pub fn finalize_psbt(mut psbt: Psbt) -> Result<Psbt, PsbtSignError> {
    use bitcoin::blockdata::witness::Witness;

    for (idx, input) in psbt.inputs.iter_mut().enumerate() {
        // If the final witness is already set, skip finalizing this input.
        if !input.final_script_witness.is_none() {
            continue;
        }
        // For P2WPKH, we expect exactly one signature; so if there's no partial signature, error.
        if input.partial_sigs.is_empty() {
            let msg = format!("Input {} has no partial signatures", idx);
            return Err(PsbtSignError::SignatureError(msg));
        }
        // For P2WPKH we expect one signature; if more than one exists, choose the first.
        // The key is a bitcoin::PublicKey.
        let (&ref pubkey, sig) = input.partial_sigs.iter().next().ok_or_else(|| {
            let msg = format!("Input {}: expected at least one signature", idx);
            PsbtSignError::SignatureError(msg)
        })?;

        // The signature is expected to be DER-encoded with the sighash flag appended.
        // If your signing code produced a bitcoin::ecdsa::Signature with the sighash flag already appended,
        // then calling `to_vec()` should yield the correct bytes.
        let mut final_sig = sig.to_vec();

        // Append SIGHASH_ALL flag (0x01) if it’s not already appended.
        if final_sig.last() != Some(&0x01) {
            final_sig.push(0x01);
        }

        // For P2WPKH the final witness should have exactly two items:
        // [signature, pubkey]
        let mut final_sig_wit = Witness::new();
        final_sig_wit.push(final_sig);
        final_sig_wit.push(pubkey.to_bytes());
        input.final_script_witness = Some(final_sig_wit);
    }

    Ok(psbt)
}
