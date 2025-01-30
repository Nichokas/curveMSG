use anyhow::Result;
use kychacha_crypto::{bytes_to_public_key, bytes_to_secret_key, decrypt, encrypt, generate_keypair, public_key_to_bytes, secret_key_to_bytes, Keypair};

fn main() -> Result<()> {
    // ============================================
    // 1. Gen of Kyber-1024 keys
    // ============================================
    let keypair = generate_keypair()?;

    // ============================================
    // 2. Serialization of keys for storage
    // ============================================
    let pk_bytes = public_key_to_bytes(&keypair.public);
    let sk_bytes = secret_key_to_bytes(&keypair.secret);

    // ============================================
    // 3. Deserialization of keys (recovery example)
    // ============================================
    let pub_key = bytes_to_public_key(&pk_bytes)?;
    let sec_key = bytes_to_secret_key(&sk_bytes)?;

    // We rebuild the complete Keypair
    let reconstructed_kp = Keypair {
        public: pub_key,
        secret: sec_key,
    };

    // ============================================
    // 4. Hybrid encryption with ChaCha20-Poly1305
    // ============================================
    let mensaje = b"super mega ultra ultra secret message";
    let encrypted_data = encrypt(&reconstructed_kp.public, mensaje)?;

    // ============================================
    // 5. Decryption using both Keypair components
    // ============================================
    let decrypted_message = decrypt(&encrypted_data, &reconstructed_kp)?;

    let mensaje_str = String::from_utf8(mensaje.to_vec())?;
    assert_eq!(decrypted_message, mensaje_str);

    Ok(())
}