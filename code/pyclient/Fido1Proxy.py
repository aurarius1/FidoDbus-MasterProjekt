import dbus


def dbus_to_array(dbus_array):
    return bytearray([byte_value for byte_value in dbus_array])


class Fido1Proxy:
    INTERFACE_NAME = "org.mp.fido1"

    def __init__(self, bus_name, object_path):
        self.proxy = dbus.Interface(
            dbus.SystemBus().get_object(bus_name, object_path),
            dbus_interface=self.INTERFACE_NAME
        )

    def make_credential(self, origin, challenge, client_data, client_data_hash, relying_party, user_entity, credential_parameters, credential_descriptors, extensions, resident_key, user_verification, authenticator_attachment, timeout_ms, attestation_conveyance_preference):
        attestation =  self.proxy.MakeCredential(
            origin,
            dbus.ByteArray(challenge),
            client_data,
            dbus.ByteArray(client_data_hash),
            relying_party,
            user_entity,
            credential_parameters,
            credential_descriptors,
            extensions,
            resident_key,
            user_verification,
            authenticator_attachment,
            timeout_ms,
            attestation_conveyance_preference
        )

        return [
            dbus_to_array(attestation[0]),
            dbus_to_array(attestation[1])
        ]

    def get_assertion(self, origin, challenge, client_data, client_data_hash, rp_id, credential_descriptor, hmac_create_secret, app_id, user_verification, timeout_ms, conditionally_mediated):
        assertion = self.proxy.GetAssertion(
            origin,
            dbus.ByteArray(challenge),
            client_data,
            dbus.ByteArray(client_data_hash),
            rp_id,
            credential_descriptor,
            hmac_create_secret,
            app_id,
            user_verification,
            timeout_ms,
            conditionally_mediated
        )

        return [
            dbus_to_array(assertion[0]),
            dbus_to_array(assertion[1]),
            dbus_to_array(assertion[2]),
            dbus_to_array(assertion[3])
        ]
