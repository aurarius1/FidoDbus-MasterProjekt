
import requests
import base64
from hashlib import sha256
import warnings
from Fido1Proxy import Fido1Proxy
import argparse


# ignore ssl warnings
warnings.filterwarnings("ignore")
ORIGIN = "https://localhost"
RPID = "localhost"
RPNAME = "Testing Server"


# basically the two functions from index.js
def b64_to_ab(b64challenge):
    return [byte for byte in base64.urlsafe_b64decode(b64challenge.encode())]


def ab_to_b64(byte_array):
    return base64.urlsafe_b64encode(byte_array).decode('utf-8')


def fetch_challenge():
    global ORIGIN
    response = requests.post(f'{ORIGIN}/challenge', verify=False)
    challenge_info = response.json()
    return challenge_info


def register_credential(rawId, clientDataJson, attestationObject):
    global ORIGIN
    credential_data = {
        'rawId': ab_to_b64(rawId),
        'response': {
            'clientDataJSON': base64.urlsafe_b64encode(clientDataJson).decode(),
            'attestationObject': ab_to_b64(attestationObject)
        }
    }

    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    response = requests.post(f'{ORIGIN}/register', json=credential_data, headers=headers, verify=False)
    response.raise_for_status() 
    return response.json()


def authenticate(raw_id, authenticator_data, client_data_json, signature, user_handle=None): 
    global ORIGIN
    response_data = {
        'rawId': ab_to_b64(raw_id), 
        'response': {
            'authenticatorData': ab_to_b64(authenticator_data),
            'clientDataJSON': base64.urlsafe_b64encode(client_data_json).decode(), 
            'signature': ab_to_b64(signature),
            'userHandle': None if user_handle is None else None
        }
    }
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    response = requests.post(f'{ORIGIN}/authenticate', json=response_data, headers=headers, verify=False)
    response.raise_for_status() 
    return response.json()


def format_client_data(challenge, type="create"): 
    global ORIGIN
    client_data_json = ("{\"challenge\":\"" + challenge + "\",\"origin\":\"" + ORIGIN + "\",\"type\":\"webauthn." + type + "\"}").encode()
    H = sha256()
    H.update(client_data_json)
    client_data_hash = H.digest()
    return client_data_json, client_data_hash


def make_credential(proxy):
    global ORIGIN, RPID, RPNAME
    print("... making credential")
    challengeInfo = fetch_challenge()
    
    client_data_json, client_data_hash = format_client_data(challengeInfo['b64challenge'])

    credential_response = proxy.make_credential(
        ORIGIN,
        b64_to_ab(challengeInfo['b64challenge']),
        client_data_json,
        client_data_hash,
        [RPID, RPNAME],
        [[65, 66, 67, 68, 69, 70, 71, 74], "testuser2@localhost", "Test User 2"],
        [["public-key"], [-7]],
        [],
        [False, False, False],
        "discouraged",  
        "preferred",
        "cross-platform",
        10000,
        ""
    )
    
    response = register_credential(credential_response[0], client_data_json, credential_response[1])
    print(response)


def get_assertion(proxy): 
    global ORIGIN, RPID
    print("... getting_assertion")
    challengeInfo = fetch_challenge()
    challenge = b64_to_ab(challengeInfo['b64challenge'])
    currentCredentialId = b64_to_ab(challengeInfo['currentCredentialId'])
    client_data_json, client_data_hash = format_client_data(challengeInfo['b64challenge'], type="get")

    assertion_response = proxy.get_assertion(
        ORIGIN,
        challenge, 
        client_data_json,
        client_data_hash,
        RPID,
        [[0, currentCredentialId]], # this represents no RK
        False, 
        "", 
        "discouraged",
        10000,
        False
    )
    
    response = authenticate(assertion_response[0], assertion_response[1], client_data_json, assertion_response[2], assertion_response[3])
    print(response)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DBUS Testscript")
    parser.add_argument('--make-credential', action='store_true', help="Call make_credential function")

    args = parser.parse_args()
    proxy = Fido1Proxy("org.mp.fido", "/org/mp/fido1")
    if args.make_credential:
        make_credential(proxy)
    get_assertion(proxy)

    
