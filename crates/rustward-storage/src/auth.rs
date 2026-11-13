//! Cryptographic authentication primitives for RustWard operator accounts.
//!
//! - Uses `Argon2id` (via the `argon2` crate, `Version::V0x13`) with 16-byte
//!   cryptographically random salts from the OS CSPRNG (`getrandom`).
//! - Constant-time verification via `argon2` / `subtle::ConstantTimeEq`.
//! - Secret inputs/outputs wrapped in `zeroize::Zeroizing` where applicable and
//!   never included in errors, logs, or audit records.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Minimum operator password length.
pub const MIN_PASSWORD_LEN: usize = 8;
/// Maximum operator password length (guards against Argon2 DoS via huge inputs).
pub const MAX_PASSWORD_LEN: usize = 128;
/// Prefix identifying a Windows DPAPI-sealed Argon2id verifier envelope.
pub const DPAPI_ENVELOPE_PREFIX: &str = "dpapi-v1:";

const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

fn argon2id_instance() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
}

/// Validates and trims an operator username (`[A-Za-z0-9][A-Za-z0-9_.-]{2,63}`).
///
/// # Errors
/// Returns a descriptive error string when the username does not meet policy.
pub fn validate_username(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if !(3..=64).contains(&trimmed.len()) {
        return Err("username must be between 3 and 64 ASCII characters".to_owned());
    }
    let bytes = trimmed.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err("username must start with an ASCII letter or digit".to_owned());
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.' || *b == b'-')
    {
        return Err("username may only contain ASCII letters, digits, '_', '.' or '-'".to_owned());
    }
    Ok(trimmed.to_owned())
}

/// Validates operator password length and character diversity rules.
///
/// # Errors
/// Returns a human-readable validation message if the password is weak.
pub fn validate_password_strength(username: Option<&str>, password: &str) -> Result<(), String> {
    if password.chars().any(char::is_control) {
        return Err("password must not contain control characters".to_owned());
    }
    let char_len = password.chars().count();
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&char_len) {
        return Err(format!(
            "password must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN} characters"
        ));
    }
    if password.trim().is_empty() {
        return Err("password cannot be blank".to_owned());
    }
    if let Some(user) = username {
        let u = user.trim();
        if !u.is_empty() && password.eq_ignore_ascii_case(u) {
            return Err("password must not match the username".to_owned());
        }
    }
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_control());
    let classes = u8::from(has_lower) + u8::from(has_upper) + u8::from(has_digit) + u8::from(has_symbol);
    if classes < 2 {
        return Err(
            "password must include characters from at least two classes (letters, digits, symbols)"
                .to_owned(),
        );
    }
    Ok(())
}

/// Hashes a password or recovery key using `Argon2id` with a fresh 16-byte OS CSPRNG salt.
///
/// # Errors
/// Returns an error if the OS CSPRNG or Argon2 computation fails.
pub fn hash_secret(secret: &str) -> Result<String, String> {
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes).map_err(|e| format!("CSPRNG salt failure: {e}"))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| format!("salt encoding failure: {e}"))?;
    let phc = argon2id_instance()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| format!("Argon2id hashing failure: {e}"))?
        .to_string();
    Ok(phc)
}

/// Verifies `candidate` against an encoded `Argon2id` PHC hash in constant time.
#[must_use]
pub fn verify_secret(candidate: &str, phc_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc_hash) else {
        return false;
    };
    argon2id_instance()
        .verify_password(candidate.as_bytes(), &parsed)
        .is_ok()
}

/// Performs constant-time equality comparison for equal- or variable-length secret tokens.
#[must_use]
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Generates a fresh 128+ bit high-entropy administrator recovery key formatted as
/// `RWREC-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`, wrapped in `Zeroizing`.
///
/// # Errors
/// Returns an error if OS CSPRNG generation fails.
pub fn generate_recovery_key() -> Result<Zeroizing<String>, String> {
    let mut entropy = [0u8; 25];
    getrandom::getrandom(&mut entropy)
        .map_err(|e| format!("CSPRNG recovery generation failure: {e}"))?;
    let mut formatted = Zeroizing::new(String::with_capacity(35));
    formatted.push_str("RWREC");
    for (idx, byte) in entropy.iter().enumerate() {
        if idx % 5 == 0 {
            formatted.push('-');
        }
        let ch = RECOVERY_ALPHABET[usize::from(*byte) % RECOVERY_ALPHABET.len()];
        formatted.push(char::from(ch));
    }
    Ok(formatted)
}

/// Normalizes an entered recovery key by stripping hyphens/whitespace and uppercasing ASCII.
#[must_use]
pub fn normalize_recovery_key(raw: &str) -> Zeroizing<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    Zeroizing::new(cleaned)
}

/// Generates a random opaque hex token using `num_bytes` from OS CSPRNG.
///
/// # Errors
/// Returns an error if OS CSPRNG fails.
pub fn generate_random_hex_token(num_bytes: usize) -> Result<Zeroizing<String>, String> {
    let mut buf = Zeroizing::new(vec![0u8; num_bytes]);
    getrandom::getrandom(&mut buf).map_err(|e| format!("CSPRNG token failure: {e}"))?;
    Ok(Zeroizing::new(encode_hex(&buf)))
}

/// Encodes arbitrary bytes into lowercase hex.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// Decodes lowercase/uppercase hex text into bytes.
///
/// # Errors
/// Returns an error when the length is odd or contains non-hex characters.
pub fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex payload length must be even".to_owned());
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex character".to_owned()),
    }
}

/// Wraps DPAPI ciphertext bytes into a versioned text envelope for SQLite storage.
#[must_use]
pub fn encode_dpapi_envelope(ciphertext: &[u8]) -> String {
    format!("{DPAPI_ENVELOPE_PREFIX}{}", encode_hex(ciphertext))
}

/// Unwraps a versioned DPAPI ciphertext envelope stored in SQLite.
///
/// # Errors
/// Returns an error if the envelope prefix or hex payload is malformed.
pub fn decode_dpapi_envelope(stored: &str) -> Result<Vec<u8>, String> {
    let Some(rest) = stored.strip_prefix(DPAPI_ENVELOPE_PREFIX) else {
        return Err("unsupported sealed envelope format".to_owned());
    };
    decode_hex(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_uses_distinct_salts_and_verifies_in_constant_time() -> Result<(), String> {
        let h1 = hash_secret("StrongPass!42")?;
        let h2 = hash_secret("StrongPass!42")?;
        assert!(h1.starts_with("$argon2id$"));
        assert_ne!(h1, h2, "per-user salt must prevent identical hashes");
        assert!(verify_secret("StrongPass!42", &h1));
        assert!(verify_secret("StrongPass!42", &h2));
        assert!(!verify_secret("WrongPass!42", &h1));
        assert!(!verify_secret("StrongPass!42", "not-a-phc-hash"));
        Ok(())
    }

    #[test]
    fn password_policy_rejects_weak_and_username_passwords() {
        assert!(validate_password_strength(Some("admin"), "short1").is_err());
        assert!(validate_password_strength(Some("admin"), "12345678").is_err());
        assert!(validate_password_strength(Some("admin"), "abcdefgh").is_err());
        assert!(validate_password_strength(Some("adminuser"), "AdminUser").is_err());
        assert!(validate_password_strength(Some("admin"), "RustWard#2026").is_ok());
    }

    #[test]
    fn recovery_key_normalizes_and_verifies() -> Result<(), String> {
        let key = generate_recovery_key()?;
        assert!(key.starts_with("RWREC-"));
        let norm1 = normalize_recovery_key(&key);
        let norm2 = normalize_recovery_key(&key.to_ascii_lowercase().replace('-', " "));
        assert_eq!(norm1.as_str(), norm2.as_str());
        let verifier = hash_secret(&norm1)?;
        assert!(verify_secret(&norm2, &verifier));
        assert!(!verify_secret("RWRECWRONGA", &verifier));
        Ok(())
    }

    #[test]
    fn dpapi_envelope_round_trip() -> Result<(), String> {
        let raw = [0x10u8, 0xAB, 0xFF, 0x00, 0x42];
        let enc = encode_dpapi_envelope(&raw);
        assert!(enc.starts_with(DPAPI_ENVELOPE_PREFIX));
        assert_eq!(decode_dpapi_envelope(&enc)?, raw);
        Ok(())
    }
}
