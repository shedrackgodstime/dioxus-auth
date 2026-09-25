/// Headless smoke run: proves the auth wiring works natively without any
/// renderer. A real app replaces this with its platform launch.
use dioxus_auth::{Auth, DefaultUserInput};

fn main() -> Result<(), dioxus_auth::AuthError> {
    let auth = Auth::memory()?;
    let (user, session) = auth.sign_up_email(
        "alice@example.com",
        "password",
        DefaultUserInput::new("alice"),
    )?;
    assert_eq!(user.name, "alice");
    let _ = auth.sign_in_email("alice@example.com", "password")?;
    auth.sign_out(&session)?;
    println!("quickstart auth flow ok for {}", user.name);
    Ok(())
}
