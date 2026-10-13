//! The short code printed in a sign-in mail beside its link, for the reader
//! whose inbox is on another device. Shared by the app's magic links and the
//! private status page sign-in.

/// Which half of the mail signed the reader in. The two variants are the only
/// values the `redeemed_via` check constraint admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemedVia {
    Link,
    Code,
}

impl RedeemedVia {
    pub fn as_str(self) -> &'static str {
        match self {
            RedeemedVia::Link => "link",
            RedeemedVia::Code => "code",
        }
    }
}

/// Crockford base32: `I`, `L`, `O` and `U` are absent, and the first three
/// fold onto the digits they are mistaken for.
const CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const CODE_LEN: usize = 6;

pub fn generate_code() -> String {
    use rand::TryRng;
    let mut bytes = [0u8; CODE_LEN];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("SysRng must succeed for a sign-in code");
    // 256 is a multiple of 32, so the modulo is uniform over the alphabet.
    bytes
        .iter()
        .map(|b| CODE_ALPHABET[usize::from(*b) % CODE_ALPHABET.len()] as char)
        .collect()
}

/// A pasted newline or a typed `O` must not read as a wrong guess.
pub fn normalize_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

/// Shape only, so a paste accident never spends the single attempt.
pub fn code_is_well_formed(normalized: &str) -> bool {
    normalized.len() == CODE_LEN && normalized.bytes().all(|b| CODE_ALPHABET.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn a_generated_code_survives_its_own_normalizer() {
        for _ in 0..200 {
            // Folding runs on every entry, so an alphabet carrying a glyph the
            // folder rewrites would mint codes that can never verify.
            let code = generate_code();
            assert_eq!(normalize_code(&code), code, "{code}");
            assert!(code_is_well_formed(&code), "{code}");
        }
    }

    #[test]
    fn the_alphabet_leaves_out_the_glyphs_the_folder_rewrites() {
        // Anything but 32 puts modulo bias back into generate_code.
        assert_eq!(CODE_ALPHABET.len(), 32);
        for confusable in [b'I', b'L', b'O', b'U'] {
            assert!(
                !CODE_ALPHABET.contains(&confusable),
                "{}",
                confusable as char
            );
        }
    }

    #[test]
    fn the_generator_reaches_every_symbol() {
        let mut seen = HashSet::new();
        for _ in 0..500 {
            seen.extend(generate_code().into_bytes());
        }
        assert_eq!(seen.len(), CODE_ALPHABET.len());
    }

    #[test]
    fn a_reader_retyping_the_code_is_not_a_wrong_guess() {
        assert_eq!(normalize_code(" 4kp-9rt\n"), "4KP9RT");
        assert_eq!(normalize_code("OIL"), "011");
    }

    #[test]
    fn shape_alone_decides_whether_an_attempt_is_spent() {
        assert!(code_is_well_formed("4KP9RT"));
        assert!(!code_is_well_formed("4KP9R"));
        assert!(!code_is_well_formed("4KP9RT7"));
        assert!(!code_is_well_formed("4KP9RU"));
    }
}
