#ifndef WEBAUTHN_H
#define WEBAUTHN_H
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif
typedef const uint8_t octet;

struct PublicKeyCredentialDescriptor{
    const octet* id;
    size_t len_id;
    octet transport;
};

struct MakeCredentialData {
    const char* origin;
    const octet* challenge;
    size_t len_challenge;
    const char* clientData;
    const octet* clientDataHash;
    size_t len_clientDataHash;

    // relying party
    const char* rpId;
    const char* rpName;

    // user entity
    const octet* userId;
    size_t len_userId;
    const char* userName;
    const char* userDisplayName;

    const char* residentKey;
    const char* userVerification;
    const char* authenticatorAttachment;

    const PublicKeyCredentialDescriptor* credentialDescriptors;
    size_t len_credentialDescriptor;

    const int32_t* coseAlgs;
    size_t len_coseAlgs;
    const char** coseAlgsTypes;
    size_t len_coseAlgsTypes;

    uint32_t timeoutMS;

    // extensions
    bool credProps;
    bool hmacCreateSecret;
    bool minPinLength;  

    const char* attestationConveyancePreference;
};

struct AttestationObject {
    octet* data;
    size_t len;
    octet* id;
    size_t len_id;
};



struct GetAssertionData{
    const char* origin;
    const octet* challenge;
    size_t len_challenge;
    const char* clientData;
    const octet* clientDataHash;
    size_t len_clientDataHash;

    const char* rpId;

    const PublicKeyCredentialDescriptor* credentialDescriptors;
    size_t len_credentialDescriptor;

    bool hmacCreateSecret;
    const char* appId;
    const char* userVerification;
    uint32_t timeoutMS;
    bool conditionallyMediated;  
};

struct GetAssertionResult{
    const octet* credentialId;
    size_t len_credentialId;
    const octet* authenticatorData;
    size_t len_authenticatorData;
    const octet* signature;
    size_t len_signature;
    const octet* userHandle;
    size_t len_userHandle;
};

AttestationObject make_credential_request(MakeCredentialData credential);
void free_make_credential_result(AttestationObject result);

GetAssertionResult get_assertion_request(GetAssertionData data);
void free_get_assertion_result(GetAssertionResult result);

#ifdef __cplusplus
}
#endif

#endif // WEBAUTHN_H
