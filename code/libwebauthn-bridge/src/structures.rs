extern crate serde;
extern crate serde_cbor;
use serde::{Serialize, Deserialize};
use serde_bytes::ByteBuf;
use std::os::raw::{c_char, c_uint, c_uchar};
use libwebauthn::proto::ctap2::Ctap2AttestationStatement;

#[repr(C)]
pub struct PublicKeyCredentialDescriptor {
    pub id: *const c_uchar,
    pub len_id: usize,
    pub transport: u8
}

// TODO CredentialDescriptors 
// firefox and library: different struct layouts: https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor
#[allow(non_snake_case)]
#[allow(unused)]
#[repr(C)]
pub struct MakeCredentialData {
    pub origin: *const c_char,
    pub challenge: *const u8,
    pub len_challenge: usize,
    pub clientData: *const c_char,
    pub clientDataHash: *const u8,
    pub len_clientDataHash: usize,
    pub rpId: *const c_char,
    pub rpName: *const c_char,
    pub userId: *const u8,
    pub len_userId: usize,
    pub userName: *const c_char,
    pub userDisplayName: *const c_char,

    pub residentKey: *const c_char,
    pub userVerification: *const c_char,
    pub authenticatorAttachment: *const c_char,

    pub credentialDescriptors: *const PublicKeyCredentialDescriptor,
    pub len_credentialdescriptors: usize,

    pub coseAlgs: *const i32,
    pub len_coseAlgs: usize,
    pub coseAlgsTypes: *const *const c_char,
    pub len_coseAlgsTypes: usize,

    pub timeoutMS: c_uint,
    pub credProps: bool,
    pub hmacCreateSecret: bool,
    pub minPinLength: bool, 

    pub attestationConveyancePreference: *const c_char
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeCredentialResult {
    #[serde(rename = "fmt")]
    pub format: String,
    #[serde(rename = "authData")]
    pub authenticator_data: ByteBuf,
    #[serde(rename = "attStmt")]
    pub attestation_statement: Ctap2AttestationStatement
}

#[repr(C)]
pub struct AttestationObject{
    pub data: *mut c_uchar,
    pub len: usize,
    pub id: *mut c_uchar,
    pub len_id: usize
}

#[allow(non_snake_case)]
#[allow(unused)]
#[repr(C)]
pub struct GetAssertionData{
    pub origin: *const c_char,
    pub challenge: *const c_uchar,
    pub len_challenge: usize,
    pub clientData: *const c_char,
    pub clientDataHash: *const c_uchar,
    pub len_clientDataHash: usize,

    pub rp_id: *const c_char,
    
    pub credentialDescriptors: *const PublicKeyCredentialDescriptor,
    pub len_credentialdescriptors: usize,

    pub hmacCreateSecret: bool,
    pub appId: *const c_char,
    pub userVerification: *const c_char,
    pub timeoutMS: u32,
    pub conditionallyMediated: bool,
}

#[allow(non_snake_case)]
#[allow(unused)]
#[repr(C)]
pub struct GetAssertionResult {
    pub credentialId: *mut c_uchar,
    pub len_credentialId: usize,
    pub authenticatorData: *mut c_uchar,
    pub len_authenticatorData: usize,
    pub signature: *mut c_uchar,
    pub len_signature: usize,
    pub userHandle: *mut c_uchar,
    pub len_userHandle: usize
}



#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct MakeCredentialsExtensions {
    #[serde(skip_serializing)]
    pub cred_props: Option<bool>,
    #[serde(rename = "hmac-secret", skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,
    #[serde(rename = "minPinLength", skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
}
