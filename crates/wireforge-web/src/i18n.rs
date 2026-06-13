//! Minimal Fluent-based i18n.
//!
//! `FluentBundle` is not Sync (it caches per-locale memoizer state), so we
//! build a fresh bundle on each lookup. This is wasteful in a hot path but
//! perfectly fine for menu strings and flash messages.

use fluent::{FluentArgs, FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

pub const SUPPORTED_LOCALES: &[&str] = &["en", "tr"];
pub const DEFAULT_LOCALE: &str = "en";

const EN_FTL: &str = include_str!("../i18n/en.ftl");
const TR_FTL: &str = include_str!("../i18n/tr.ftl");

fn source_for(locale: &str) -> &'static str {
    match locale {
        "tr" => TR_FTL,
        _ => EN_FTL,
    }
}

fn build_bundle(locale: &str) -> FluentBundle<FluentResource> {
    let lang: LanguageIdentifier = locale
        .parse()
        .unwrap_or_else(|_| "en".parse().expect("en langid"));
    let resource =
        FluentResource::try_new(source_for(locale).to_string()).expect("ftl parse");
    let mut bundle = FluentBundle::new(vec![lang]);
    let _ = bundle.add_resource(resource);
    bundle
}

/// Negotiate the best locale from a raw `Accept-Language` header value.
pub fn negotiate(accept_language: Option<&str>) -> &'static str {
    let Some(header) = accept_language else {
        return DEFAULT_LOCALE;
    };
    for part in header.split(',') {
        let tag = part.split(';').next().unwrap_or("").trim();
        if tag.is_empty() {
            continue;
        }
        let primary = tag.split('-').next().unwrap_or(tag);
        if let Some(locale) = SUPPORTED_LOCALES.iter().find(|l| **l == primary) {
            return *locale;
        }
    }
    DEFAULT_LOCALE
}

/// Translate `key` in `locale`, falling back to the key itself if missing.
pub fn t(locale: &str, key: &str) -> String {
    t_args(locale, key, None)
}

pub fn t_args(locale: &str, key: &str, args: Option<&FluentArgs>) -> String {
    let locale = if SUPPORTED_LOCALES.contains(&locale) {
        locale
    } else {
        DEFAULT_LOCALE
    };
    let bundle = build_bundle(locale);
    if let Some(msg) = bundle.get_message(key).and_then(|m| m.value()) {
        let mut errors = vec![];
        let out = bundle.format_pattern(msg, args, &mut errors);
        return out.into_owned();
    }
    if locale != DEFAULT_LOCALE {
        let fallback = build_bundle(DEFAULT_LOCALE);
        if let Some(msg) = fallback.get_message(key).and_then(|m| m.value()) {
            let mut errors = vec![];
            let out = fallback.format_pattern(msg, args, &mut errors);
            return out.into_owned();
        }
    }
    key.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiates_tr() {
        assert_eq!(negotiate(Some("tr-TR,tr;q=0.9,en;q=0.8")), "tr");
    }

    #[test]
    fn falls_back_to_default() {
        assert_eq!(negotiate(Some("zh-CN")), "en");
        assert_eq!(negotiate(None), "en");
    }

    #[test]
    fn translates_basic_key() {
        assert_eq!(t("en", "nav-dashboard"), "Dashboard");
        assert_eq!(t("tr", "nav-dashboard"), "Kontrol paneli");
        assert_eq!(t("en", "no-such-key"), "no-such-key");
    }
}
