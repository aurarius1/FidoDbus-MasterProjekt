
use std::process::{Command, Stdio};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::hid::HidDevice;
use libwebauthn::transport::Device;
use libwebauthn::ops::webauthn::{
    MakeCredentialRequest, GetAssertionRequest, GetAssertionResponse
};
use libwebauthn::proto::ctap2::Ctap2MakeCredentialResponse;

use libwebauthn::pin::{PinProvider};
use libwebauthn::webauthn::{Error as WebAuthnError, WebAuthn, CtapError};
use tokio::runtime::Runtime;
use dialog::DialogBox;
use dialog::backends::KDialog;

use crate::pin::KDialogPinProvider;

fn select_token(tokens: &[HidDevice]) -> Option<usize> {
    if tokens.is_empty() {
        // Display an abort message if tokens are empty
        let abort_message = "Please plug in a token and restart the process.";
        Command::new("kdialog")
            .args(&["--error", abort_message])
            .stderr(Stdio::piped())
            .output()
            .expect("Failed to execute kdialog");
        return None;
    }
    let mut args: Vec<String> = vec!["--radiolist".to_string(), "Select your token!".to_string()];
    let mut tag = 0;
    for opt in tokens {
        args.push(tag.to_string());
        args.push(opt.to_string());
        args.push(if tag == 0 { "on".to_string() } else { "off".to_string() });
        tag += 1;
    }

    let output = Command::new("kdialog")
            .args(&args)
            .stderr(Stdio::piped())
            .output().
            expect("Failed to execute kdialog");

    if output.status.success() {
        let selected_option = String::from_utf8(output.stdout).expect("Invalid UTF-8");
        let selected_option = selected_option.trim();
        if let Some(index) = selected_option.parse::<usize>().ok() {
            if index < tokens.len() {
                return Some(index);
            }
        }
    } else {
        let error_output = String::from_utf8(output.stderr).unwrap_or_else(|_| String::from("Unknown error"));
        eprintln!("{}", error_output);
    }
    None
}


pub fn make_credentials_request(request: MakeCredentialRequest) -> Option<Ctap2MakeCredentialResponse>{ // Result<Ctap2MakeCredentialResponse, Box<dyn Error>> {
    let mut _dialog = KDialog::new();
    let choice = dialog::Question::new("Give access to tokens?")
    .show()
    .expect("Could not display dialog box");
    
    if choice == dialog::Choice::No{
        return None;
    }

    let pin_provider: Box<dyn PinProvider> = Box::new(KDialogPinProvider::new());
    let rt = Runtime::new().unwrap();
    let tokens = rt.block_on(async {
        let devices = list_devices().await.unwrap();
        devices
    });
    // Call the method to select from options
    if let Some(selected_device) = select_token(&tokens) {
        let result = rt.block_on(async {
            for (i, mut device) in tokens.into_iter().enumerate() {
                if i == selected_device {
                    device.wink(request.timeout).await?;
                    let mut channel = device.channel().await?;
                    let response = loop {
                        match channel.webauthn_make_credential(&request, &pin_provider).await {
                            Ok(response) => break Ok(response),
                            Err(WebAuthnError::Ctap(ctap_error)) if ctap_error.is_retryable_user_error() => {
                                println!("Try again! Error: {}", ctap_error);
                            }
                            Err(err) => {
                                return Err(Box::new(err));
                            }, // Propagate the error
                        };
                    };
                    match response {
                        Ok(response) => return Ok(response),
                        Err(err) => {
                            eprintln!("{}", err);
                            return Err(Box::new(err));
                        }
                    }
                }
            }
            return Err(Box::new(WebAuthnError::Ctap(CtapError::Other)));
        });
        match result {
            Ok(response) => return Some(response),
            _ => {
                return None;
            }
        }
    }
    None
}


pub fn get_assertion_request(get_assertion: GetAssertionRequest) -> Option<GetAssertionResponse>{
    let pin_provider: Box<dyn PinProvider> = Box::new(KDialogPinProvider::new());
    let rt = Runtime::new().unwrap();
    let tokens = rt.block_on(async {
        let devices = list_devices().await.unwrap();
        devices
    });
    // Call the method to select from options
    if let Some(selected_device) = select_token(&tokens) {
        let result = rt.block_on(async {
            for (i, mut device) in tokens.into_iter().enumerate() {
                if i == selected_device {
                    device.wink(get_assertion.timeout).await?;
                    let mut channel = device.channel().await?;
                    let response = loop {
                        match channel
                            .webauthn_get_assertion(&get_assertion, &pin_provider)
                            .await
                        {
                            Ok(response) => break Ok(response),
                            Err(WebAuthnError::Ctap(ctap_error)) => {
                                if ctap_error.is_retryable_user_error() {
                                    println!("Oops, try again! Error: {}", ctap_error);
                                    continue;
                                }
                                break Err(WebAuthnError::Ctap(ctap_error));
                            }
                            Err(err) => break Err(err),
                        };
                    };
                    match response {
                        Ok(response) => return Ok(response),
                        Err(err) => {
                            eprintln!("ciao {}", err);
                            return Err(Box::new(err));
                        }
                    }
                }
            }
            return Err(Box::new(WebAuthnError::Ctap(CtapError::Other)));
        });
        match result {
            Ok(response) => return Some(response),
            _ => {
                return None;
            }
        }
    }
    None
}