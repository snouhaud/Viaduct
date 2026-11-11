// Copyright (c) 2002-2026 Brent Simmons, Ranchero Software
// Copyright (c) 2026 Brandon LaRocque
// Licensed under the MIT License. See LICENSE in the project root for details.

//! Sync Account dialog (NNW `263ec2683`'s update path for
//! username/password accounts), covering the Reader API services:
//! Inoreader and self-hosted FreshRSS. Credentials are verified against
//! the service before being stored, so a typo can't silently kill sync.
//! The account is chosen at startup, so a service switch applies on the
//! next launch.

use gtk::glib;
use gtk::prelude::*;

use crate::network::credentials::{
    Credentials, delete_credentials, fetch_credentials, store_credentials,
};
use crate::network::inoreader::{ReaderAPICaller, ReaderAPIVariant, freshrss_api_base};
use crate::ui::rows;
use crate::ui::window::ViaductWindow;

/// Dropdown order; index ↔ variant.
const SERVICES: [ReaderAPIVariant; 2] = [ReaderAPIVariant::Inoreader, ReaderAPIVariant::FreshRSS];

fn selected_variant(dropdown: &gtk::DropDown) -> ReaderAPIVariant {
    SERVICES
        .get(dropdown.selected() as usize)
        .copied()
        .unwrap_or(ReaderAPIVariant::Inoreader)
}

/// Build and present the dialog. Fields pre-fill from the Secret Service
/// where credentials already exist; Save verifies against the service and
/// only then stores, so the previously-working token survives a failed
/// attempt untouched.
pub fn present(parent: &ViaductWindow) {
    let group = rows::group(
        Some("Sync account"),
        Some(
            "The Reader API service viaduct syncs with. Saving verifies the credentials first; a failed verification leaves the stored ones untouched. For FreshRSS, enable API access and use the API password set in your FreshRSS profile.",
        ),
    );
    let names: Vec<&str> = SERVICES.iter().map(|v| v.display_name()).collect();
    let (service_row, service_dropdown) = rows::combo_row("Service", None, &names);
    let (server_row, server_entry) =
        rows::entry_row(Some("Server"), None, None, Some("https://rss.example.org"));
    let (email_row, email_entry) =
        rows::entry_row(Some("Username"), None, None, Some("you@example.com"));
    let (token_row, token_entry) =
        rows::entry_row(Some("Password"), None, None, Some("App / API password"));
    token_entry.set_visibility(false);
    token_entry.set_input_purpose(gtk::InputPurpose::Password);
    group.add(&service_row);
    group.add(&server_row);
    group.add(&email_row);
    group.add(&token_row);
    server_row.set_visible(false);

    let server_row_for_toggle = server_row.clone();
    service_dropdown.connect_selected_notify(move |dd| {
        server_row_for_toggle.set_visible(selected_variant(dd) == ReaderAPIVariant::FreshRSS);
    });

    let status = gtk::Label::builder()
        .halign(gtk::Align::Start)
        .wrap(true)
        .visible(false)
        .build();

    // Pre-fill from the stored credentials, in the same order the account
    // is picked at startup (best-effort; a locked or empty keyring just
    // leaves the fields blank). spawn_future_local: the widgets cross the
    // keyring await, so the future stays on the main loop.
    {
        let dropdown = service_dropdown.clone();
        let server_entry = server_entry.clone();
        let email_entry = email_entry.clone();
        let token_entry = token_entry.clone();
        glib::spawn_future_local(async move {
            // The keyring lookup (zbus) needs the tokio reactor, so it runs
            // on the library runtime; only the widget updates stay here.
            let found = crate::spawn_on_runtime(async {
                for (index, variant) in SERVICES.iter().enumerate() {
                    if let Some(creds) =
                        fetch_credentials(variant.account_id()).await.ok().flatten()
                    {
                        return Some((index, creds));
                    }
                }
                None
            })
            .await
            .ok()
            .flatten();
            if let Some((index, creds)) = found {
                dropdown.set_selected(index as u32);
                server_entry.set_text(creds.server.as_deref().unwrap_or_default());
                email_entry.set_text(&creds.username);
                token_entry.set_text(creds.password.as_deref().unwrap_or_default());
            }
        });
    }

    let buttons = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .halign(gtk::Align::End)
        .spacing(12)
        .build();
    let cancel = gtk::Button::builder().label("Cancel").build();
    let save = gtk::Button::builder()
        .label("Verify and Save")
        .css_classes(["suggested-action"])
        .build();
    buttons.append(&cancel);
    buttons.append(&save);

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(24)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    content.append(group.widget());
    content.append(&status);
    content.append(&buttons);

    let window = gtk::Window::builder()
        .title("Sync Account")
        .transient_for(parent)
        .modal(true)
        .default_width(480)
        .default_height(360)
        .child(&content)
        .build();
    crate::ui::close_on_escape(&window);

    let window_for_cancel = window.clone();
    cancel.connect_clicked(move |_| {
        window_for_cancel.close();
    });

    let window_for_save = window.clone();
    let status_for_save = status.clone();
    let save_for_save = save.clone();
    save.connect_clicked(move |_| {
        let variant = selected_variant(&service_dropdown);
        let server = server_entry.text().trim().to_string();
        let email = email_entry.text().trim().to_string();
        let token = token_entry.text().trim().to_string();
        let window = window_for_save.clone();
        let status = status_for_save.clone();
        let save_btn = save_for_save.clone();
        if email.is_empty() || token.is_empty() {
            status.set_text("Both the username and the password are required.");
            status.set_visible(true);
            return;
        }
        let is_freshrss = variant == ReaderAPIVariant::FreshRSS;
        if is_freshrss && server.is_empty() {
            status.set_text("The FreshRSS server address is required.");
            status.set_visible(true);
            return;
        }
        // Verify against the service; store only on success. The button
        // disables for the round trip so a slow check can't be
        // double-submitted.
        save_btn.set_sensitive(false);
        status.set_text(&format!("Verifying against {}…", variant.display_name()));
        status.set_visible(true);
        glib::spawn_future_local(async move {
            // Network (reqwest) and keyring (zbus) calls need the tokio
            // reactor: run them on the library runtime and only touch
            // widgets back here on the main loop.
            let outcome = crate::spawn_on_runtime(async move {
                verify_and_store(variant, server, email, token).await
            })
            .await
            .unwrap_or_else(|e| Err(format!("internal error: {e}")));
            let switched = match outcome {
                Ok(switched) => switched,
                Err(msg) => {
                    save_btn.set_sensitive(true);
                    status.set_text(&msg);
                    status.set_visible(true);
                    return;
                }
            };
            window.close();
            if let Some(parent) = window
                .transient_for()
                .and_then(|p| p.downcast::<ViaductWindow>().ok())
            {
                let msg = if switched {
                    format!(
                        "{} account saved. Restart viaduct to switch syncing to it.",
                        variant.display_name()
                    )
                } else {
                    format!(
                        "{} credentials saved. Restart viaduct if sync was not already active.",
                        variant.display_name()
                    )
                };
                parent.show_toast_public(&msg);
            }
        });
    });

    window.present();
}

/// Verify `email`/`token` against `variant`, store them, and drop the
/// other services' credentials (one sync account at a time, so the
/// startup pick lands on the one just saved). Returns whether another
/// service was replaced. Must run on the tokio runtime.
async fn verify_and_store(
    variant: ReaderAPIVariant,
    server: String,
    email: String,
    token: String,
) -> Result<bool, String> {
    let is_freshrss = variant == ReaderAPIVariant::FreshRSS;
    let caller = if is_freshrss {
        ReaderAPICaller::with_base_url(variant, &freshrss_api_base(&server))
    } else {
        ReaderAPICaller::new(variant)
    };
    caller
        .validate_credentials(&email, &token)
        .await
        .map_err(|e| format!("{} rejected these credentials: {e}", variant.display_name()))?;
    let creds = Credentials {
        username: email,
        password: Some(token),
        server: is_freshrss.then_some(server),
    };
    store_credentials(variant.account_id(), &creds)
        .await
        .map_err(|e| format!("Verified, but storing failed: {e}"))?;
    let mut switched = false;
    for other in SERVICES.iter().filter(|v| **v != variant) {
        if fetch_credentials(other.account_id())
            .await
            .ok()
            .flatten()
            .is_some()
        {
            switched = true;
            if let Err(e) = delete_credentials(other.account_id()).await {
                tracing::warn!(
                    ?e,
                    service = other.display_name(),
                    "could not remove old credentials"
                );
            }
        }
    }
    Ok(switched)
}
