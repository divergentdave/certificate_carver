use std::borrow::Cow;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug)]
pub enum Error {
    ProhibitedCharacter(char),
    ProhibitedBidirectionalText,
}

pub fn ldapprep_case_insensitive(s: &'_ str) -> Result<Cow<'_, str>, Error> {
    // Prepares strings for caseIgnoreMatch comparisons per RFC 5280 § 7.1, which refers to
    // RFC 4518.

    // RFC 4518 § 2.2. Map (with case folding)
    let mapped = s
        .chars()
        .filter(|&c| !stringprep::tables::commonly_mapped_to_nothing(c))
        .flat_map(stringprep::tables::case_fold_for_nfkc);

    // RFC 4518 § 2.3. Normalize
    let normalized = mapped.nfkc().collect::<String>();

    // RFC 4518 § 2.4. Prohibit
    let prohibited = normalized.chars().find(|&c| {
        stringprep::tables::unassigned_code_point(c)
            || stringprep::tables::change_display_properties_or_deprecated(c)
            || stringprep::tables::private_use(c)
            || stringprep::tables::non_character_code_point(c)
            || stringprep::tables::surrogate_code(c)
            || c == '\u{FFFD}' // "REPLACEMENT CHARACTER"
    });
    if let Some(c) = prohibited {
        return Err(Error::ProhibitedCharacter(c));
    }

    // RFC 4518 § 2.5. Check bidi
    if is_prohibited_bidrectional_text(&normalized) {
        return Err(Error::ProhibitedBidirectionalText);
    }

    // RFC 4518 § 2.6.1. Insignificant Space Handling
    if normalized.chars().any(|c| c != ' ') {
        let words = normalized.split_whitespace().collect::<Vec<_>>();
        let mut result = words.join("  ");
        result.insert(0, ' ');
        result.push(' ');
        Ok(Cow::Owned(result))
    } else {
        Ok(Cow::Owned(String::from("  ")))
    }
}

fn is_prohibited_bidrectional_text(s: &str) -> bool {
    if s.contains(stringprep::tables::bidi_r_or_al) {
        if s.contains(stringprep::tables::bidi_l) {
            return true;
        }
        if !stringprep::tables::bidi_r_or_al(s.chars().next().unwrap())
            || !stringprep::tables::bidi_r_or_al(s.chars().next_back().unwrap())
        {
            return true;
        }
    }
    false
}
