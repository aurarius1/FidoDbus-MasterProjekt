
use libwebauthn::pin::{PinProvider};
use async_trait::async_trait;
use std::process::Command;


pub struct KDialogPinProvider {

}

impl KDialogPinProvider {
    pub fn new() -> Self {
        Self { }
    }

    fn show_password_dialog(&self, attempts: u32) -> Option<String> {
        // Using KDialog directly to create a password dialog
        let output = Command::new("kdialog")
            .arg("--password")
            .arg(format!("Please enter your pin!\n{} tries left", attempts))
            .output()
            .expect("Failed to execute kdialog");

        if output.status.success() {
            let pin = String::from_utf8_lossy(&output.stdout);
            Some(pin.trim().to_string())
        } else {
            None
        }
    }
}

#[async_trait]
impl PinProvider for KDialogPinProvider {
    async fn provide_pin(&self, attempts_left: Option<u32>) -> Option<String> {
        let mut attempts = 0;
        if let Some(attempts_left) = attempts_left {
            attempts = attempts_left;
        }
        let pin = self.show_password_dialog(attempts);


        match pin {
            Some(pin) => {
                return Some(pin);
            },
            None => return None
        };
    }
}