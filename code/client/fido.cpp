#include "fido.h"
#include <cstring>

template <typename T>
struct DbusTypeTraits;
template <>
struct DbusTypeTraits<uint8_t> {
    static constexpr int dbusType = DBUS_TYPE_BYTE;
    static constexpr const char* dbusTypeAsString = DBUS_TYPE_BYTE_AS_STRING;
};
template <>
struct DbusTypeTraits<std::string> {
    static constexpr int dbusType = DBUS_TYPE_STRING;
    static constexpr const char* dbusTypeAsString = DBUS_TYPE_STRING_AS_STRING;
};
template <>
struct DbusTypeTraits<int32_t> {
    static constexpr int dbusType = DBUS_TYPE_INT32;
    static constexpr const char* dbusTypeAsString = DBUS_TYPE_INT32_AS_STRING;
};
template <>
struct DbusTypeTraits<uint32_t> {
    static constexpr int dbusType = DBUS_TYPE_UINT32;
    static constexpr const char* dbusTypeAsString = DBUS_TYPE_UINT32_AS_STRING;
};
template <>
struct DbusTypeTraits<bool> {
    static constexpr int dbusType = DBUS_TYPE_BOOLEAN;
    static constexpr const char* dbusTypeAsString = DBUS_TYPE_BOOLEAN_AS_STRING;
};

template <typename T>
bool addToDbusRequest(DBusMessageIter &container, const T& content){
  //this is not very nice but ok
  if constexpr (std::is_same<T, bool>::value) {
    int val = content ? 1 : 0;
    if (!dbus_message_iter_append_basic(&container, DbusTypeTraits<T>::dbusType, &val)) {
      return false;
    }   
  }
  else{
    if (!dbus_message_iter_append_basic(&container, DbusTypeTraits<T>::dbusType, &content)) {
      return false;
    }   
  }
  
  return true;
}

template <typename T>
bool addArrayToDbusRequest(DBusMessageIter &container, const std::vector<T>& content){
  DBusMessageIter subContainer;
  bool ret = true;
  if(!dbus_message_iter_open_container(&container, DBUS_TYPE_ARRAY, DbusTypeTraits<T>::dbusTypeAsString, &subContainer)){
    return false;
  }
  for (size_t i = 0; i < content.size() && ret; i++) {
    ret = addToDbusRequest(subContainer, content.at(i));
  }
  if(!dbus_message_iter_close_container(&container, &subContainer)){
    ret = false;
  }
  return ret;
}

template <typename T>
bool addMembersToDbusRequest(DBusMessageIter &iter, const T &member) {
  return addToDbusRequest(iter, member);
}

template <typename T>
bool addMembersToDbusRequest(DBusMessageIter &iter, const std::vector<T> &member) {
  return addArrayToDbusRequest(iter, member);
}

template <typename T, typename... Args>
bool addMembersToDbusRequest(DBusMessageIter &iter, const T &first, const Args&... args) {
  if (!addMembersToDbusRequest(iter, first)) {
    return false;
  }
  return addMembersToDbusRequest(iter, args...);
}

template <typename... Args>
bool addStructToDbusRequest(DBusMessageIter &container, Args... args) {
  DBusMessageIter structContainer;
  bool ret = true;
  if (!dbus_message_iter_open_container(&container, DBUS_TYPE_STRUCT, NULL, &structContainer)) {
    return false;
  }

  if (!addMembersToDbusRequest(structContainer, args...)) {
    ret = false;
  }

  if (!dbus_message_iter_close_container(&container, &structContainer)) {
    ret = false;
  }

  return ret;
}

bool addArrayOfCredentialDescriptorToDbusRequest(DBusMessageIter &container, const std::vector<fido_dbus::CredentialDescriptor> content){
  DBusMessageIter subContainer;
  bool ret = true;
  if(!dbus_message_iter_open_container(&container, DBUS_TYPE_ARRAY, "(yay)", &subContainer)){
      return false;
  }
  for (size_t i = 0; i < content.size() && ret; i++) {
    ret = addStructToDbusRequest(subContainer, content.at(i).transports, content.at(i).credentialIds);
  }
  if(!dbus_message_iter_close_container(&container, &subContainer)){
      ret = false;
  }
  return ret;
}


template <typename T>
bool copyDbusResponseIntoVector(DBusMessageIter &container, std::vector<T> &dst, bool nullable = false){
  DBusMessageIter array;
  dbus_message_iter_recurse(&container, &array);
  const T* byte_array;
  int byte_array_len;
  dbus_message_iter_get_fixed_array(&array, &byte_array, &byte_array_len);
  dst.resize(byte_array_len);
  memcpy((void*)dst.data(), byte_array, byte_array_len);
  return nullable || byte_array_len != 0;
}


namespace fido_dbus{



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
) noexcept{
  fido_dbus::Result result = fido_dbus::Result::SUCCESS;
  DBusConnection *conn;
  DBusError err;
  DBusMessage *msg;
  DBusMessageIter args, struct_iter, array_iter;
  const char * dbus_result = nullptr;
  dbus_error_init(&err);  
  conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
  DBusMessage * dbus_reply = nullptr;

  // Compose remote procedure call
  msg = ::dbus_message_new_method_call("org.mp.fido", "/org/mp/fido1", "org.mp.fido1", "MakeCredential");
  ::dbus_message_iter_init_append(msg, &args);

  // parse params to dbus form
  {
    if(!addToDbusRequest(args, origin)){
      std::cerr << "Failed to add origin parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addArrayToDbusRequest(args, challenge)){
      std::cerr << "Failed to add challenge parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addToDbusRequest(args, clientData)){
      std::cerr << "Failed to add clientData parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addArrayToDbusRequest(args, clientDataHash)){
      std::cerr << "Failed to add clientDataHash parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addStructToDbusRequest(args, relyingParty.id, relyingParty.name)){
      std::cerr << "Failed to add relying party parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addStructToDbusRequest(args, user.id, user.name, user.displayName)){
      std::cerr << "Failed to add user entity parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addStructToDbusRequest(args, credentialParameters.type, credentialParameters.coseAlgs)){
      std::cerr << "Failed to add credentialParameters parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addArrayOfCredentialDescriptorToDbusRequest(args, credentialDescriptors)){
      std::cerr << "Failed to add credentialDescriptors parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addStructToDbusRequest(args, extensions.credProps, extensions.hmacCreateSecret, extensions.minPinLength)){
      std::cerr << "Failed to add extensions parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addToDbusRequest(args, residentKey)){
      std::cerr << "Failed to add residentKey parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addToDbusRequest(args, userVerification)){
      std::cerr << "Failed to add userVerification parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    } 
    if(!addToDbusRequest(args, authenticatorAttachment)){
      std::cerr << "Failed to add authenticatorAttachment parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addToDbusRequest(args, timeoutMS)){
      std::cerr << "Failed to add timeoutMS parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto make_cred_end;
    }
    if(!addToDbusRequest(args, attestationConveyancePreference)){
      std::cerr << "Failed to add attestationConveyancePreference parameter to dbus request" << std::endl;
    result = fido_dbus::Result::DBUS_ERROR;
    goto make_cred_end;
    }
  }

  // actual dbus call
  dbus_reply = ::dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
  if(dbus_reply == nullptr){
    std::cerr << err.message << "\n";
    result = fido_dbus::Result::DBUS_ERROR;
    goto make_cred_end;
  }
  ::dbus_message_get_args(dbus_reply, &err, DBUS_TYPE_STRING, &dbus_result, DBUS_TYPE_INVALID);


  dbus_message_iter_init(dbus_reply, &struct_iter); 
  if (dbus_message_iter_get_arg_type(&struct_iter) != DBUS_TYPE_STRUCT) {
    std::cerr << "Unexpected type, expected STRUCT!" << std::endl;
    result = fido_dbus::Result::DBUS_ERROR;
    goto make_cred_cleanup;
  }
  dbus_message_iter_recurse(&struct_iter, &array_iter);
  if (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_ARRAY) {
    std::cerr << "Unexpected type, expected ARRAY!" << std::endl;
    result = fido_dbus::Result::DBUS_ERROR;
    goto make_cred_cleanup;
  }
  
  if(!copyDbusResponseIntoVector(array_iter, makeCredentialResult.credentialId)){
    result =  fido_dbus::Result::ABORTED;
    goto make_cred_cleanup;
  }
  dbus_message_iter_next(&array_iter);
  if(!copyDbusResponseIntoVector(array_iter, makeCredentialResult.attestationObject)){
    result =  fido_dbus::Result::ABORTED;
    goto make_cred_cleanup;
  }
make_cred_cleanup:
    if (dbus_reply != nullptr) {
        dbus_message_unref(dbus_reply);
    }
make_cred_end:
    if (msg != nullptr) {
        dbus_message_unref(msg);
    }
    if (conn != nullptr) {
        dbus_connection_unref(conn);
    }
  return result;
}


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
) noexcept{
  fido_dbus::Result result = fido_dbus::Result::SUCCESS;
  DBusConnection *conn;
  DBusError err;
  DBusMessage *msg;
  DBusMessageIter args, struct_iter, array_iter;
  const char * dbus_result = nullptr;
  dbus_error_init(&err);  
  conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
  DBusMessage * dbus_reply = nullptr;

  // Compose remote procedure call
  msg = ::dbus_message_new_method_call("org.mp.fido", "/org/mp/fido1", "org.mp.fido1", "GetAssertion");
  ::dbus_message_iter_init_append(msg, &args);

  // parse params to dbus form
  {
    if(!addToDbusRequest(args, origin)){
      std::cerr << "Failed to add origin parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addArrayToDbusRequest(args, challenge)){
      std::cerr << "Failed to add challenge parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addToDbusRequest(args, clientData)){
      std::cerr << "Failed to add clientData parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addArrayToDbusRequest(args, clientDataHash)){
      std::cerr << "Failed to add clientDataHash parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addToDbusRequest(args, rpId)){
      std::cerr << "Failed to add rpId parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addArrayOfCredentialDescriptorToDbusRequest(args, credentialDescriptors)){
      std::cerr << "Failed to add credentialDescriptors parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addToDbusRequest(args, hmacCreateSecret)){
      std::cerr << "Failed to add hmacCreateSecret parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addToDbusRequest(args, appId)){
      std::cerr << "Failed to add appId parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addToDbusRequest(args, userVerification)){
      std::cerr << "Failed to add hmacCreateSecret parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addToDbusRequest(args, timeoutMS)){
      std::cerr << "Failed to add timeoutMS parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
    if(!addToDbusRequest(args, conditionallyMediated)){
      std::cerr << "Failed to add conditionallyMediated parameter to dbus request" << std::endl;
      result = fido_dbus::Result::DBUS_ERROR;
      goto get_assertion_end;
    }
  }


   // actual dbus call
  dbus_reply = ::dbus_connection_send_with_reply_and_block(conn, msg, DBUS_TIMEOUT_USE_DEFAULT, &err);
  if(dbus_reply == nullptr){
    std::cerr << err.message << "\n";
    result = fido_dbus::Result::DBUS_ERROR;
    goto get_assertion_end;
  }
  ::dbus_message_get_args(dbus_reply, &err, DBUS_TYPE_STRING, &dbus_result, DBUS_TYPE_INVALID);


  dbus_message_iter_init(dbus_reply, &struct_iter); 
  if (dbus_message_iter_get_arg_type(&struct_iter) != DBUS_TYPE_STRUCT) {
    std::cerr << "Unexpected type, expected STRUCT!" << std::endl;
    result = fido_dbus::Result::DBUS_ERROR;
    goto get_assertion_cleanup;
  }
  dbus_message_iter_recurse(&struct_iter, &array_iter);
  if (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_ARRAY) {
    std::cerr << "Unexpected type, expected ARRAY!" << std::endl;
    result = fido_dbus::Result::DBUS_ERROR;
    goto get_assertion_cleanup;
  }
  
  if(!copyDbusResponseIntoVector(array_iter, assertion.credentialId)){
    result =  fido_dbus::Result::ABORTED;
    goto get_assertion_cleanup;
  }
  dbus_message_iter_next(&array_iter);
  if(!copyDbusResponseIntoVector(array_iter, assertion.authenticatorData)){
    result =  fido_dbus::Result::ABORTED;
    goto get_assertion_cleanup;
  }
  dbus_message_iter_next(&array_iter);
  if(!copyDbusResponseIntoVector(array_iter, assertion.signature)){
    result =  fido_dbus::Result::ABORTED;
    goto get_assertion_cleanup;
  }
  dbus_message_iter_next(&array_iter);
  if(!copyDbusResponseIntoVector(array_iter, assertion.userHandle, true)){
    result =  fido_dbus::Result::ABORTED;
    goto get_assertion_cleanup;
  }
get_assertion_cleanup:
  if (dbus_reply != nullptr) {
      dbus_message_unref(dbus_reply);
  }
get_assertion_end:
  if (msg != nullptr) {
      dbus_message_unref(msg);
  }
  if (conn != nullptr) {
      dbus_connection_unref(conn);
  }
  return result;
}
}
