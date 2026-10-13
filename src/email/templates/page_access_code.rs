//! The sign-in mail of a private status page, in the page's language: a code
//! for the tab that asked, and a link for the reader on another device.

use crate::email::templates::layout::{self, ButtonStyle, Page};
use crate::email::templates::{MARKUP_SLOT, RenderedEmail, fill_slot, html_escape};
use crate::i18n::Tr;

pub fn render(
    tr: Tr,
    site_name: &str,
    page_name: &str,
    url: &str,
    code: &str,
    expires_in_minutes: u32,
) -> RenderedEmail {
    let page = || page_name.into();
    let subject = tr.t_args("email-access-subject", [("page", page())]);
    let expiry = tr.t_args(
        "email-access-expiry",
        [("minutes", expires_in_minutes.into())],
    );
    let not_you = tr.t("email-access-not-you");

    let text_body = format!(
        "{lead}\n\
         \n  {code}\n\
         \n\
         {link}\n\
         \n  {url}\n\
         \n\
         {expiry}\n\
         {not_you}\n",
        lead = tr.t_args("email-access-lead", [("page", page())]),
        link = tr.t("email-access-link"),
    );

    let mut body = layout::paragraph(&fill_slot(
        &tr.t_args("email-access-lead", [("page", MARKUP_SLOT.into())]),
        &format!("<strong>{}</strong>", html_escape(page_name)),
    ));
    body.push_str(&layout::code_block(code));
    body.push_str(&layout::paragraph(&html_escape(&tr.t("email-access-link"))));
    body.push_str(&layout::button(
        url,
        &tr.t_args("email-access-button", [("page", page())]),
        ButtonStyle::Outline,
    ));
    body.push_str(&layout::fine_print(&html_escape(&expiry)));

    let html_body = layout::render_in(
        tr.lang(),
        Page {
            title: &subject,
            preheader: &tr.t_args(
                "email-access-preheader",
                [("minutes", expires_in_minutes.into())],
            ),
            signature: Some(site_name),
            header: layout::wordmark(site_name, &tr.t("email-access-heading")),
            body,
            footnote: Some(layout::fine_print(&html_escape(&not_you))),
        },
    );

    RenderedEmail {
        subject,
        text_body,
        html_body,
    }
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::domain::Locale;
    use crate::i18n::Tr;

    #[test]
    fn the_code_and_the_link_both_reach_the_reader() {
        let r = render(
            Tr::default(),
            "Uptimepage",
            "Autohaus Weber IT",
            "https://weber.example.test/access/verify?token=x",
            "4KP9RT",
            15,
        );
        assert!(r.subject.contains("Autohaus Weber IT"));
        for body in [&r.text_body, &r.html_body] {
            assert!(body.contains("4KP9RT"));
            assert!(body.contains("/access/verify?token=x"));
            assert!(body.contains("15"));
        }
    }

    #[test]
    fn a_german_page_mails_its_code_in_german() {
        let r = render(
            Tr::new(Locale::De),
            "Uptimepage",
            "Autohaus & Co",
            "https://weber.example.test/access/verify?token=x",
            "4KP9RT",
            15,
        );
        assert!(r.html_body.contains(r#"<html lang="de">"#));
        assert!(r.html_body.contains("<strong>Autohaus &amp; Co</strong>"));
        assert!(r.subject.contains("Autohaus & Co"));
        for body in [&r.subject, &r.text_body, &r.html_body] {
            assert!(
                !body.contains(['\u{2068}', '\u{2069}', '\u{E000}']),
                "{body}"
            );
        }
    }
}
