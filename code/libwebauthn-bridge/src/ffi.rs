
use std::ptr;
use std::time::Duration;
use libwebauthn::ops::webauthn::{
    MakeCredentialRequest as LibMakeCredentialRequest, GetAssertionRequest
};
use libwebauthn::proto::ctap2::Ctap2PublicKeyCredentialDescriptor;
extern crate serde;
extern crate serde_cbor;
use crate::structures::*;
use crate::bridge;


#[no_mangle]
pub extern "C" fn make_credential_request(credential: MakeCredentialData) -> AttestationObject{
    let request = LibMakeCredentialRequest {
        origin: credential.origin().to_string(),
        hash: credential.client_data_hash().to_owned(),
        relying_party: credential.relying_party(),
        user: credential.user(),
        require_resident_key: credential.resident_key(),
        user_verification: credential.user_verification(),
        algorithms: credential.algorithms(),
        exclude: credential.credential_descriptors(), 
        extensions_cbor: vec![], //credential.extensions(), 
        timeout: Duration::from_secs((credential.timeoutMS/1000).into()),  
    };

    match bridge::make_credentials_request(request) {
        Some(response) => {
            let credential: Ctap2PublicKeyCredentialDescriptor = (&response).try_into().unwrap();
            let credential_id: Vec<u8> = credential.id.to_vec();
            let result = MakeCredentialResult{
                format: response.format,
                authenticator_data: response.authenticator_data,
                attestation_statement: response.attestation_statement,
            };
            let result = match serde_cbor::to_vec(&result){
                Ok(result) => result,
                _ => {
                    return AttestationObject::default();
                }
            };
            let mut vec = result.into_boxed_slice();
            let mut id_vec = credential_id.into_boxed_slice();

            let attestation_object = AttestationObject{
                data: vec.as_mut_ptr(),
                len: vec.len(),
                id: id_vec.as_mut_ptr(),
                len_id: id_vec.len()
            };

            std::mem::forget(vec);
            std::mem::forget(id_vec);
           
            attestation_object
        }, 
        None => {
            return AttestationObject::default();
        }
    }
}


#[no_mangle]
pub extern "C" fn free_make_credential_result(obj: AttestationObject) {
    if !obj.data.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(obj.data, obj.len, obj.len);
        }
    }

    if !obj.id.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(obj.id, obj.len_id, obj.len_id);
        }
    }
}


#[no_mangle]
pub extern "C" fn get_assertion_request(data: GetAssertionData) -> GetAssertionResult {

    let request = GetAssertionRequest {
        relying_party_id: data.rp_id().to_owned(),
        hash: data.client_data_hash(),
        allow: data.credential_descriptors(),
        user_verification: data.user_verification(),
        extensions_cbor: None, //Some(vec![data.hmac_create_secret()])
        timeout: Duration::from_secs((data.timeoutMS/1000).into()),  
    };
    match bridge::get_assertion_request(request) {
        Some(response) => {
           
            let credential_id = match &response.assertions[0].credential_id {
                Some(cred) => cred.id.clone().into_vec(),
                _ => {
                    return GetAssertionResult::default();
                }
            };

            let authenticator_data = response.assertions[0].authenticator_data.clone().into_vec();
            let signature =response.assertions[0].signature.clone().into_vec();
            let mut authenticator_data = authenticator_data.into_boxed_slice();
            let mut signature = signature.into_boxed_slice();
            let mut credential_id = credential_id.into_boxed_slice(); 

            let assertion_result = GetAssertionResult{
                credentialId: credential_id.as_mut_ptr(),
                len_credentialId: credential_id.len(),
                authenticatorData: authenticator_data.as_mut_ptr(),
                len_authenticatorData: authenticator_data.len(),
                signature: signature.as_mut_ptr(),
                len_signature: signature.len(),
                userHandle: ptr::null_mut(),
                len_userHandle: 0,
            };


            std::mem::forget(authenticator_data);
            std::mem::forget(signature);
            std::mem::forget(credential_id);
            assertion_result
        }
        _ => {
            GetAssertionResult::default()
        }
    }
}

#[no_mangle]
pub extern "C" fn free_get_assertion_result(obj: GetAssertionResult) {
    if !obj.authenticatorData.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(obj.authenticatorData, obj.len_authenticatorData, obj.len_authenticatorData);
        }
    }

    if !obj.signature.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(obj.signature, obj.len_signature, obj.len_signature);
        }
    }

    if !obj.userHandle.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(obj.userHandle, obj.len_userHandle, obj.len_userHandle);
        }
    }

    
}