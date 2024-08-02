#include <sdbus-c++/sdbus-c++.h>
#include "fido-server-glue.h"
#include <iostream>
#include "webauthn.h"
#include <cstring>


typedef sdbus::Struct<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>,  std::vector<uint8_t>> GetAssertionResponse;
typedef sdbus::Struct<std::vector<uint8_t>, std::vector<uint8_t>> MakeCredentialResponse;


class Fido : public sdbus::AdaptorInterfaces<org::mp::fido1_adaptor /*, more adaptor classes if there are more interfaces*/>
{
public:
    Fido(sdbus::IConnection& connection, std::string objectPath)
        : AdaptorInterfaces(connection, std::move(objectPath))
    {
        registerAdaptor();
    }

    ~Fido()
    {
        unregisterAdaptor();
    }

protected:
    MakeCredentialResponse MakeCredential(
        const std::string& origin, const std::vector<uint8_t>& challenge, const std::string& clientData, 
        const std::vector<uint8_t>& clientDataHash, const sdbus::Struct<std::string, std::string>& relyingParty, 
        const sdbus::Struct<std::vector<uint8_t>, std::string, std::string>& userEntity, 
        const sdbus::Struct<std::vector<std::string>, std::vector<int32_t>>& credentialParamters, 
        const std::vector<sdbus::Struct<uint8_t, std::vector<uint8_t>>>& credentialDescriptor, 
        const sdbus::Struct<bool, bool, bool>& extensions, const std::string& residentKey, 
        const std::string& userVerification, const std::string& authenticatorAttachment, 
        const uint32_t& timeoutMS, const std::string& attestationConveyancePreference)
    {
        std::vector<PublicKeyCredentialDescriptor> credentialDescriptors;
        for(auto& descriptor : credentialDescriptor){
            credentialDescriptors.push_back(PublicKeyCredentialDescriptor {
                .id = descriptor.get<1>().data(),
                .len_id = descriptor.get<1>().size(),
                .transport = descriptor.get<0>(),
            });
        }

        std::vector<const char*> coseAlgTypesCStyle;
        for(auto& coseAlgType : credentialParamters.get<0>()){
            coseAlgTypesCStyle.push_back(coseAlgType.c_str());
        }
        
        
        MakeCredentialData credential = {
            .origin = origin.c_str(),
            .challenge = challenge.data(),
            .len_challenge = challenge.size(),
            .clientData = clientData.c_str(),
            .clientDataHash = clientDataHash.data(),
            .len_clientDataHash = clientDataHash.size(),
            
            .rpId = relyingParty.get<0>().c_str(),
            .rpName = relyingParty.get<1>().c_str(),

            .userId = userEntity.get<0>().data(),
            .len_userId = userEntity.get<0>().size(),
            .userName = userEntity.get<1>().c_str(),
            .userDisplayName = userEntity.get<2>().c_str(),

            .residentKey = residentKey.c_str(),
            .userVerification = userVerification.c_str(),
            .authenticatorAttachment = authenticatorAttachment.c_str(),
            

            .credentialDescriptors = credentialDescriptors.data(),
            .len_credentialDescriptor = credentialDescriptors.size(),

            .coseAlgs = credentialParamters.get<1>().data(),
            .len_coseAlgs = credentialParamters.get<1>().size(),
            .coseAlgsTypes = coseAlgTypesCStyle.data(),
            .len_coseAlgsTypes = coseAlgTypesCStyle.size(),

            .timeoutMS = timeoutMS,
            .credProps = extensions.get<0>(),
            .hmacCreateSecret = extensions.get<1>(),
            .minPinLength = extensions.get<2>(),

            .attestationConveyancePreference = attestationConveyancePreference.c_str()
        };
        AttestationObject result = make_credential_request(credential);
        std::vector<uint8_t> attestationObject(result.len);
        memcpy(attestationObject.data(), result.data, result.len);

        std::vector<uint8_t> rawId(result.len_id);
        memcpy(rawId.data(), result.id, result.len_id);

        // Free the memory allocated by Rust
        free_make_credential_result(result);

        MakeCredentialResponse ret(rawId, attestationObject);   
        return ret;
    
    }


    GetAssertionResponse GetAssertion(const std::string& origin, const std::vector<uint8_t>& challenge, 
        const std::string& clientData, const std::vector<uint8_t>& clientDataHash, const std::string& rpId, 
        const std::vector<sdbus::Struct<uint8_t, std::vector<uint8_t>>>& credentialDescriptor, 
        const bool& hmacCreateSecret, const std::string& appId, const std::string& userVerification, 
        const uint32_t& timeoutMS, const bool& conditionallyMediated) 
    {
        std::vector<PublicKeyCredentialDescriptor> credentialDescriptors;
        for(auto& descriptor : credentialDescriptor){
            credentialDescriptors.push_back(PublicKeyCredentialDescriptor {
                .id = descriptor.get<1>().data(),
                .len_id = descriptor.get<1>().size(),
                .transport = descriptor.get<0>(),
            });
        }


        GetAssertionData assertionData = {
            .origin = origin.c_str(), 
            .challenge = challenge.data(),
            .len_challenge = challenge.size(),
            .clientData = clientData.c_str(),
            .clientDataHash = clientDataHash.data(),
            .len_clientDataHash = clientDataHash.size(),

            .rpId = rpId.c_str(),

            .credentialDescriptors = credentialDescriptors.data(),
            .len_credentialDescriptor = credentialDescriptors.size(),

            .hmacCreateSecret = hmacCreateSecret,
            .appId = appId.c_str(),
            .userVerification = userVerification.c_str(),
            .timeoutMS = timeoutMS,
            .conditionallyMediated = conditionallyMediated
        };

        GetAssertionResult assertionResult = get_assertion_request(assertionData);
    
        std::vector<uint8_t> credentialId(assertionResult.len_credentialId);
        memcpy(credentialId.data(), assertionResult.credentialId, assertionResult.len_credentialId);

        std::vector<uint8_t> authenticatorData(assertionResult.len_authenticatorData);
        memcpy(authenticatorData.data(), assertionResult.authenticatorData, assertionResult.len_authenticatorData);

        std::vector<uint8_t> signature(assertionResult.len_signature);
        memcpy(signature.data(), assertionResult.signature, assertionResult.len_signature);
        
        std::vector<uint8_t> userHandle(assertionResult.len_userHandle);
        memcpy(userHandle.data(), assertionResult.userHandle, assertionResult.len_userHandle);

        free_get_assertion_result(assertionResult);
        
        GetAssertionResponse response(credentialId, authenticatorData, signature, userHandle);
        return response;
    }


};





