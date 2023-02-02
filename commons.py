import json
from base64 import b64decode, b64encode
from hashlib import sha3_256
from os import path, stat
from secrets import token_bytes

import nacl.secret
import requests
from ecdsa import ECDH, NIST384p, SigningKey, VerifyingKey

import pki

# The url the flask srever listens on; used by both the journalist and the source clients
SERVER = "127.0.0.1:5000"
# The folder where everybody will load the keys from. There is no separation for demo simplicity
# of course in an actual implementation, everybody will only have their keys and the
# required public one to ensure the trust chain
DIR = "keys/"
# Where the flask server will store uploaded files
UPLOADS = "files/"
# Folders where journalists download attachments to submissions
DOWNLOADS = "downloads/"
# How many journalists do we create and enroll. In general, this is realistic, in current
# securedrop usage it is way less
JOURNALISTS = 10
# How many ephemeral keys each journalist create, sign and auploads when required
ONETIMEKEYS = 30
# The curve for all elliptic curve operations. It must be imported first from the python-ecdsa
# library. Ed25519 and Ed448, although supported by the lib, are not fully implemented
CURVE = NIST384p
# How may challenges the server sends to each party when they try to fetch messages
# This basically must be more than the msssages in the database, otherwise we need
# to develop a mechanism to group challenges adding some bits of metadata
CHALLENGES = 500
# The seconds for which a challenge_id remains valid
CHALLENGES_TTL = 30
# The base size of every parts in which attachment are splitted/padded to. This
# is not the actual size on disk, cause thet will be a bit more depending on
# the nacl SecretBox implementation
CHUNK = 512 * 1024


def add_journalist(journalist_key, journalist_sig, journalist_chal_key, journalist_chal_sig):
    journalist_uid = sha3_256(journalist_key.verifying_key.to_string()).hexdigest()
    journalist_key = b64encode(journalist_key.verifying_key.to_string()).decode("ascii")
    journalist_sig = b64encode(journalist_sig).decode("ascii")
    journalist_chal_key = b64encode(journalist_chal_key.verifying_key.to_string()).decode("ascii")
    journalist_chal_sig = b64encode(journalist_chal_sig).decode("ascii")

    response = requests.post(f"http://{SERVER}/journalists", json={
                "journalist_key": journalist_key,
                "journalist_sig": journalist_sig,
                "journalist_chal_key": journalist_chal_key,
                "journalist_chal_sig": journalist_chal_sig
    })
    assert (response.status_code == 200)
    return journalist_uid


def get_journalists(intermediate_verifying_key):
    response = requests.get(f"http://{SERVER}/journalists")
    assert (response.status_code == 200)
    journalists = response.json()["journalists"]
    assert (len(journalists) == JOURNALISTS)
    for content in journalists:
        journalist_verifying_key = pki.public_b642key(content["journalist_key"])
        journalist_chal_verifying_key = pki.public_b642key(content["journalist_chal_key"])
        # pki.verify_key shall give an hard fault is a signature is off
        pki.verify_key(intermediate_verifying_key,
                       journalist_verifying_key,
                       None,
                       b64decode(content["journalist_sig"])
                       )
        pki.verify_key(intermediate_verifying_key,
                       journalist_chal_verifying_key,
                       None,
                       b64decode(content["journalist_chal_sig"])
                       )
    return journalists


def get_ephemeral_keys(journalists):
    response = requests.get(f"http://{SERVER}/ephemeral_keys")
    assert (response.status_code == 200)
    ephemeral_keys = response.json()["ephemeral_keys"]
    assert (len(ephemeral_keys) == JOURNALISTS)
    ephemeral_keys_return = []
    checked_uids = set()
    for ephemeral_key_dict in ephemeral_keys:
        journalist_uid = ephemeral_key_dict["journalist_uid"]
        for journalist in journalists:
            if journalist_uid == journalist["journalist_uid"]:
                ephemeral_key_dict["journalist_uid"] = journalist["journalist_uid"]
                ephemeral_key_dict["journalist_key"] = journalist["journalist_key"]
                ephemeral_key_dict["journalist_chal_key"] = journalist["journalist_chal_key"]
                # add uids to a set
                checked_uids.add(journalist_uid)
                journalist_verifying_key = pki.public_b642key(journalist["journalist_key"])
        ephemeral_verifying_key = pki.public_b642key(ephemeral_key_dict["ephemeral_key"])
        # We rely again on verify_key raising an exception in case of failure
        pki.verify_key(journalist_verifying_key,
                       ephemeral_verifying_key,
                       None,
                       b64decode(ephemeral_key_dict["ephemeral_sig"]))
        ephemeral_keys_return.append(ephemeral_key_dict)
    # check that all keys are from different journalists
    assert (len(checked_uids) == JOURNALISTS)
    return ephemeral_keys_return


def build_message(challenge_public_key, encryption_public_key):
    challenge_public_key = VerifyingKey.from_string(b64decode(challenge_public_key), curve=CURVE)
    encryption_public_key = VerifyingKey.from_string(b64decode(encryption_public_key), curve=CURVE)

    ecdh = ECDH(curve=CURVE)
    # [SOURCE] PERMESSAGE-EPHEMERAL KEY (private)
    message_key = SigningKey.generate(curve=CURVE)
    message_public_key = b64encode(message_key.verifying_key.to_string()).decode("ascii")
    # load the private key to generate the shared secret
    ecdh.load_private_key(message_key)

    # [JOURNALIST] PERMESSAGE-EPHEMERAL KEY (public)
    ecdh.load_received_public_key(encryption_public_key)
    # generate the secret for encrypting the secret with the source_ephemeral+journo_ephemeral
    # so that we have forward secrecy
    encryption_shared_secret = ecdh.generate_sharedsecret_bytes()

    # encrypt the message, we trust nacl safe defaults
    box = nacl.secret.SecretBox(encryption_shared_secret[0:32])

    # generate the shared secret for the challenge/response using
    # source_ephemeral+journo_longterm
    # [JOURNALIST] LONG-TERM CHALLENGE KEY

    # generate the message challenge to send the server
    message_challenge = b64encode(VerifyingKey.from_public_point(
        pki.get_shared_secret(challenge_public_key, message_key),
        curve=CURVE).to_string()).decode('ascii')

    return message_public_key, message_challenge, box


def send_message(message_ciphertext, message_public_key, message_challenge):
    send_dict = {"message_ciphertext": message_ciphertext,
                 "message_public_key": message_public_key,
                 "message_challenge": message_challenge}

    response = requests.post(f"http://{SERVER}/message", json=send_dict)
    if response.status_code != 200:
        return False
    else:
        return response.json()


def send_file(encrypted_file):
    file_dict = {"file": encrypted_file}

    response = requests.post(f"http://{SERVER}/file", files=file_dict)
    if response.status_code != 200:
        return False
    else:
        return response.json()


def get_file(file_id):
    response = requests.get(f"http://{SERVER}/file/{file_id}")
    if response.status_code != 200:
        return False
    else:
        return response.content


def get_challenges():
    response = requests.get(f"http://{SERVER}/challenge")
    assert (response.status_code == 200)
    return response.json()["challenge_id"], response.json()["message_challenges"]


def send_messages_challenges_responses(challenge_id, message_challenges_responses):
    message_challenges_responses_dict = {"message_challenges_responses": message_challenges_responses}
    response = requests.post(f"http://{SERVER}/challenge/{challenge_id}",
                             json=message_challenges_responses_dict)
    if response.status_code != 200:
        return False
    else:
        return response.json()


def get_message(message_id):
    response = requests.get(f"http://{SERVER}/message/{message_id}")
    assert (response.status_code == 200)
    assert ("message" in response.json())
    return response.json()["message"]


def delete_message(message_id):
    response = requests.delete(f"http://{SERVER}/message/{message_id}")
    assert (response.status_code == 200)
    return response.status_code == 200


def fetch_messages_id(challenge_key):
    challenge_id, message_challenges = get_challenges()

    inv_secret = pki.ec_mod_inverse(challenge_key)
    inv_journalist = SigningKey.from_secret_exponent(inv_secret, curve=CURVE)

    message_challenges_responses = []

    for message_challenge in message_challenges:
        message_challenges_response = VerifyingKey.from_public_point(
                            pki.get_shared_secret(
                                pki.public_b642key(message_challenge), inv_journalist
                            ),
                            curve=CURVE
                        )
        message_challenges_responses.append(
            b64encode(message_challenges_response.to_string()).decode('ascii')
        )

    res = send_messages_challenges_responses(challenge_id, message_challenges_responses)
    if res:
        messages = res["messages"]
        return messages


def fetch_messages_content(messages_id):
    messages_list = []
    for message_id in messages_id:
        messages_list.append(get_message(message_id))
        return messages_list


def decrypt_message_asymmetric(private_key, message_public_key, message_ciphertext):
    ecdh = ECDH(curve=CURVE)
    ecdh.load_private_key(private_key)
    ecdh.load_received_public_key_bytes(b64decode(message_public_key))
    encryption_shared_secret = ecdh.generate_sharedsecret_bytes()
    box = nacl.secret.SecretBox(encryption_shared_secret[0:32])
    try:
        message_plaintext = json.loads(box.decrypt(b64decode(message_ciphertext)).decode('ascii'))
        return message_plaintext
    except Exception:
        return False


def upload_message(content):
    assert (len(content) < CHUNK)
    key = token_bytes(32)
    box = nacl.secret.SecretBox(key)
    ciphertext = box.encrypt(content.ljust(CHUNK).encode('ascii'))
    upload_response = send_file(ciphertext)
    return upload_response['file_id'], key.hex()


def decrypt_message_symmetric(ciphertext, key):
    box = nacl.secret.SecretBox(key)
    plaintext = json.loads(box.decrypt(ciphertext).decode('ascii'))
    return plaintext


def upload_attachment(filename):
    try:
        size = stat(filename).st_size

    except Exception:
        return False

    attachment = {"name": path.basename(filename),
                  "size": size,
                  "parts": []}
    parts_count = 0
    read_size = 0
    with open(filename, "rb") as f:
        key = token_bytes(32)
        # Read file in chunks so that we do not consume too much memory
        # And we can make all chunks equal and pad the last one
        while read_size < size:
            part = f.read(CHUNK)
            part_len = len(part)
            read_size += part_len

            box = nacl.secret.SecretBox(key)
            encrypted_part = box.encrypt(part.ljust(CHUNK))

            upload_response = send_file(encrypted_part)

            part = {"number": parts_count,
                    "id": upload_response["file_id"],
                    "size": part_len,
                    "key": key.hex()}
            attachment["parts"].append(part)
            parts_count += 1

    attachment["parts_count"] = parts_count

    return attachment
