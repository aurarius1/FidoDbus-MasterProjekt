use libwebauthn::ops::webauthn::UserVerificationRequirement;
use libwebauthn::proto::ctap2::{
    Ctap2Transport, Ctap2PublicKeyCredentialDescriptor, 
    Ctap2PublicKeyCredentialType, Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialRpEntity
, Ctap2PublicKeyCredentialUserEntity};
use crate::structures::{
    GetAssertionData, MakeCredentialData, GetAssertionResult, AttestationObject
};
use serde_bytes::ByteBuf;
use std::ptr;


pub fn u8_to_transport(transport: u8) -> Option<Vec<Ctap2Transport>> {
    // see https://github.com/microsoft/webauthn/blob/master/webauthn.h#L280
    match transport {
        0 => Some(vec![Ctap2Transport::BLE, Ctap2Transport::USB, Ctap2Transport::NFC]), //unrestricted, 
        1 => Some(vec![Ctap2Transport::USB]), 
        2 => Some(vec![Ctap2Transport::NFC]), 
        4 => Some(vec![Ctap2Transport::BLE]),
        _ => None // ignoring unknown/unsupported values 
    }
}

pub  fn uv_string_to_enum(uv: &str) -> UserVerificationRequirement{
    match uv.to_lowercase().as_str() {
        "required" => UserVerificationRequirement::Required,
        "preferred" => UserVerificationRequirement::Preferred,
        "discouraged" => UserVerificationRequirement::Discouraged,
        _ => {
            eprintln!("Error: invalid userVerification");
            UserVerificationRequirement::Discouraged
        }
    }
}

// contains safe getters for the assertion data
#[allow(dead_code)]
impl GetAssertionData {
    pub fn origin(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.origin).to_str().unwrap() }
    }

    pub fn challenge(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.challenge, self.len_challenge).to_vec() }
    }

    pub fn client_data(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.clientData).to_str().unwrap() }
    }

    pub fn client_data_hash(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.clientDataHash, self.len_clientDataHash).to_vec() }
    }

    pub fn rp_id(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.rp_id).to_str().unwrap() }
    }

    pub fn app_id(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.appId).to_str().unwrap() }
    }

    pub fn credential_descriptors(&self) -> Vec<Ctap2PublicKeyCredentialDescriptor> {
        let descriptors = unsafe { std::slice::from_raw_parts(self.credentialDescriptors, self.len_credentialdescriptors) };
        descriptors.iter().map(|descriptor| {
            let id = unsafe { std::slice::from_raw_parts(descriptor.id, descriptor.len_id).to_vec() };
            Ctap2PublicKeyCredentialDescriptor {
                // only type in xdg-credentials-portal
                r#type: Ctap2PublicKeyCredentialType::PublicKey, 
                id: ByteBuf::from(id),
                transports: u8_to_transport(descriptor.transport),
            }
        }).collect()
    }

    pub fn user_verification(&self) -> UserVerificationRequirement {
        let uv = unsafe { std::ffi::CStr::from_ptr(self.userVerification).to_str().unwrap()};
        uv_string_to_enum(uv)
    }

    pub fn extensions(&self) -> Vec<u8> {
        vec![]
    }

    pub fn timeout_ms(&self) -> u32 {
        self.timeoutMS
    }

    pub fn conditionally_mediated(&self) -> bool {
        self.conditionallyMediated
    }
}



// contains safe getters for make credential data
#[allow(dead_code)]
impl MakeCredentialData {
    pub fn origin(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.origin).to_str().unwrap() }
    }

    pub fn challenge(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.challenge, self.len_challenge).to_vec() }
    }

    pub fn client_data(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.clientData).to_str().unwrap() }
    }

    pub fn client_data_hash(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.clientDataHash, self.len_clientDataHash).to_vec() }
    }

    fn rp_id(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.rpId).to_str().unwrap() }
    }

    fn rp_name(&self) -> &str {
        unsafe { std::ffi::CStr::from_ptr(self.rpName).to_str().unwrap() }
    }

    pub fn relying_party(&self) -> Ctap2PublicKeyCredentialRpEntity {
        Ctap2PublicKeyCredentialRpEntity::new(self.rp_id(), self.rp_name())
    }

    fn user_id(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.userId, self.len_userId).to_vec() }
    }

    fn user_name(&self) -> &str {
        unsafe {std::ffi::CStr::from_ptr(self.userName).to_str().unwrap()}
    }

    fn user_display_name(&self) -> &str {
        unsafe {std::ffi::CStr::from_ptr(self.userDisplayName).to_str().unwrap()}
    }

    pub fn user(&self) -> Ctap2PublicKeyCredentialUserEntity{
        Ctap2PublicKeyCredentialUserEntity::new(&self.user_id(), self.user_name(), self.user_display_name())
    }

    pub fn resident_key(&self) -> bool {
        let rk = unsafe {std::ffi::CStr::from_ptr(self.residentKey).to_str().unwrap()};
        match rk.to_lowercase().as_str() {
            "required" => true,
            "discouraged" => false,
            "" => false,
            "preferred" => true,
            _ => {
                // return default false
                eprintln!("Error: invalid residentKey");
                false 
            }
        }
        
    }

    pub fn user_verification(&self) -> UserVerificationRequirement {
        let uv = unsafe { std::ffi::CStr::from_ptr(self.userVerification).to_str().unwrap()};
        uv_string_to_enum(uv)
    }

    pub fn authenticator_attachment(&self) -> &str {
        unsafe {std::ffi::CStr::from_ptr(self.authenticatorAttachment).to_str().unwrap()}
    }

    pub fn algorithms(&self) -> Vec<Ctap2CredentialType>{
        let cose_algs = unsafe { std::slice::from_raw_parts(self.coseAlgs, self.len_coseAlgs) };
        let mut algorithms = Vec::new();
        for &cose_alg in cose_algs {
  
            let algorithm = match cose_alg {
                -7 => Ctap2COSEAlgorithmIdentifier::ES256,
                -8 => Ctap2COSEAlgorithmIdentifier::EDDSA,
                -9 => Ctap2COSEAlgorithmIdentifier::TOPT,
                _ => continue,
            };
            let public_key_type = Ctap2PublicKeyCredentialType::PublicKey;
            let algorithm = Ctap2CredentialType {
                public_key_type,
                algorithm,
            };

            algorithms.push(algorithm);
        }
        if algorithms.is_empty(){
            panic!("EMPTY ALGORITHMS")
        }
        algorithms
    }

    pub fn credential_descriptors(&self) -> Option<Vec<Ctap2PublicKeyCredentialDescriptor>> {
        let descriptors = unsafe { std::slice::from_raw_parts(self.credentialDescriptors, self.len_credentialdescriptors) };
        Some(descriptors.iter().map(|descriptor| {
            let id = unsafe { std::slice::from_raw_parts(descriptor.id, descriptor.len_id).to_vec() };
            Ctap2PublicKeyCredentialDescriptor {
                // only type in xdg-credentials-portal
                r#type: Ctap2PublicKeyCredentialType::PublicKey, 
                id: ByteBuf::from(id),
                transports: u8_to_transport(descriptor.transport),
            }
        }).collect())
    }

    pub fn extensions(&self) -> Vec<u8> {
        vec![]

        /*
        
        let extensions = MakeCredentialsExtensions {
            min_pin_length: Some(true),
            ..Default::default() // This sets the other fields to their default values (None)
        };

        
        let cbor_data = match serde_cbor::to_vec(&extensions) {
            Ok(cbor_data) => {
                // Print the CBOR data
                println!("{:?}", cbor_data);
                cbor_data
            }
            Err(e) => {
                eprintln!("Error serializing to CBOR: {}", e);
                vec![]
            }
        };
        for byte in &cbor_data {
            print!("{:02x}", byte);
        }
        println!("");*/


        // Parsing the cbor extensions like shown above would be possible (cbor.me reports the correct thing)
        // but when libweauthn parses the complete Request object again, the Vec<u8> would be interpreted as
        // an array, therefore the resulting cbor byte string would not contain a map at the given position: 
        // this is an example cbor string that can be checked with cbor.me and 6: reports an array if it is decoded 
        // A7015820825B1B2240B2F0FBE1471B385D0AFB4E35A9F7E576BE96FD182382E0C88E79D802A2626964696C6F63616C686F7374646E616D656E54657374696E672053657276657203A362696448414243444546474A646E616D6573746573747573657232406C6F63616C686F73746B646973706C61794E616D656B54657374205573657220320481A264747970656A7075626C69632D6B657963616C6726068F18A1186C186D1869186E18501869186E184C1865186E18671874186818F408582000DD0FC2A1CB02D210D83C09605907D5314F3843339B24350E04C98FBE1548350902
    }

    pub fn attestation_conveyance_preference(&self) -> &str{
        unsafe { std::ffi::CStr::from_ptr(self.attestationConveyancePreference).to_str().unwrap() }
    }

}


impl Default for GetAssertionResult {
    fn default() -> Self {
        GetAssertionResult {
            credentialId: ptr::null_mut(),
            len_credentialId: 0,
            authenticatorData: ptr::null_mut(),
            len_authenticatorData: 0,
            signature: ptr::null_mut(),
            len_signature: 0,
            userHandle: ptr::null_mut(),
            len_userHandle: 0,
        }
    }
}

impl Default for AttestationObject {
    fn default() -> Self {
        AttestationObject {
            data: ptr::null_mut(),
            len: 0,
            id: ptr::null_mut(),
            len_id: 0,
        }
    }
}
