//! Brand-name normalization.
//!
//! Names (display names, aliases) are only used for duplicate detection,
//! search and *hints*. They never authorize a device.

/// Fold Turkish and common Latin diacritics to ASCII, upper-case, trim and
/// collapse whitespace and punctuation. `"ÜRETİCİ  ÖRNEK"`, `"Uretici Ornek"`
/// and `"URETICI-ORNEK"` all normalize to `"URETICI ORNEK"`.
#[must_use]
pub fn normalize_brand_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending_space = false;
    for c in name.chars() {
        let folded: &str = match c {
            'İ' | 'I' | 'ı' | 'i' | 'Í' | 'í' | 'Î' | 'î' | 'Ï' | 'ï' => "I",
            'Ü' | 'ü' | 'Ú' | 'ú' | 'Û' | 'û' | 'Ù' | 'ù' => "U",
            'Ö' | 'ö' | 'Ó' | 'ó' | 'Ô' | 'ô' | 'Ò' | 'ò' => "O",
            'Ç' | 'ç' => "C",
            'Ş' | 'ş' => "S",
            'Ğ' | 'ğ' => "G",
            'Â' | 'â' | 'Á' | 'á' | 'À' | 'à' | 'Ä' | 'ä' => "A",
            'É' | 'é' | 'È' | 'è' | 'Ê' | 'ê' | 'Ë' | 'ë' => "E",
            _ => "",
        };
        if !folded.is_empty() {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.push_str(folded);
        } else if c.is_ascii_alphanumeric() {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.push(c.to_ascii_uppercase());
        } else if c.is_alphanumeric() {
            // Other scripts: keep, upper-cased.
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.extend(c.to_uppercase());
        } else {
            pending_space = true;
        }
    }
    out
}

/// Derive a catalog slug (`[a-z0-9-]{1,32}`) from a display name.
/// Returns `None` if nothing usable remains.
#[must_use]
pub fn slug_from_name(name: &str) -> Option<String> {
    let normalized = normalize_brand_name(name);
    let mut slug = String::new();
    for c in normalized.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if c == ' ' && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug: String = slug.trim_matches('-').chars().take(32).collect();
    let slug = slug.trim_end_matches('-').to_owned();
    (!slug.is_empty()).then_some(slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turkish_names_fold_consistently() {
        let expected = "URETICI ORNEK";
        for v in [
            "ÜRETİCİ ÖRNEK",
            "Üretici Örnek",
            "uretici-ornek",
            "  URETICI   ORNEK ",
            "ÜRETİCİ/ÖRNEK",
        ] {
            assert_eq!(normalize_brand_name(v), expected, "{v}");
        }
        assert_eq!(normalize_brand_name("ŞÇĞÖÜıİ"), "SCGOUII");
        assert_eq!(normalize_brand_name("SanDisk, Inc."), "SANDISK INC");
        assert_eq!(normalize_brand_name("---"), "");
    }

    #[test]
    fn slugs_are_catalog_safe() {
        assert_eq!(
            slug_from_name("ÜRETİCİ ÖRNEK").as_deref(),
            Some("uretici-ornek")
        );
        assert_eq!(
            slug_from_name("Western Digital (WD)").as_deref(),
            Some("western-digital-wd")
        );
        assert_eq!(slug_from_name("!!!"), None);
        let long = slug_from_name(&"a b ".repeat(40)).unwrap();
        assert!(long.len() <= 32 && !long.ends_with('-'));
    }
}
