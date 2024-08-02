#ifndef FIDO_H
#define FIDO_H

#include <dbus/dbus.h>
#include <iostream>
#include <string>
#include <vector>

namespace fido_dbus{

struct RelyingParty{
    std::string id;
    std::string name;
};

struct UserEntity{
    std::vector<uint8_t> id;
    std::string name;
    std::string displayName;
};

struct CredentialParameters{
    std::vector<std::string> type;
    std::vector<int32_t> coseAlgs;
};

struct CredentialDescriptor{
    uint8_t transports;
    std::vector<uint8_t> credentialIds;
};

struct Extensions {
    bool credProps;
    bool hmacCreateSecret;
    bool minPinLength;
};


struct Attestation{
    std::vector<uint8_t> attestationObject;
    std::vector<uint8_t> credentialId;
};

struct Assertion{
    std::vector<uint8_t> credentialId;
    std::vector<uint8_t> authenticatorData;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> userHandle;
};

enum Result {
    SUCCESS, 
    DBUS_ERROR,
    ABORTED,
    ERROR
};

Result MakeCredential(
    const std::string& origin,
    const std::vector<uint8_t>& challenge, 
    const std::string& clientData,
    const std::vector<uint8_t>& clientDataHash, 
    const RelyingParty& relyingParty,
    const UserEntity& user,
    const CredentialParameters& credentialParameters,
    const std::vector<CredentialDescriptor>& credentialDescriptors,
    const Extensions& extensions,
    const std::string& residentKey,
    const std::string& userVerification, 
    const std::string& authenticatorAttachment,
    const uint32_t& timeoutMS,
    const std::string& attestationConveyancePreference, 

    Attestation& makeCredentialResult
) noexcept;


Result GetAssertion(
    const std::string& origin,
    const std::vector<uint8_t>& challenge, 
    const std::string& clientData,
    const std::vector<uint8_t>& clientDataHash, 
    const std::string& rpId,
    const std::vector<CredentialDescriptor>& credentialDescriptors,
    const bool hmacCreateSecret,
    const std::string& appId,
    const std::string& userVerification,
    const uint32_t& timeoutMS,
    const bool conditionallyMediated,

    Assertion& assertion
) noexcept;
}
#endif // FIDO_H