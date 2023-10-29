import json
from base64 import b64encode
from hashlib import sha3_256
from os import path, stat
from secrets import token_bytes

import requests
from nacl.encoding import Base64Encoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import VerifyKey

import pki

# The url the flask srever listens on; used by both the journalist and the source clients
SERVER = "127.0.0.1:5000"
# The folder where everybody will load the keys from. There is no separation for demo simplicity
# of course in an actual implementation, everybody will only have their keys and the
# required public one to ensure the trust chain
DIR = "keys/"
# Where the flask server will store uploaded files
UPLOADS = "files/"
# How many journalists do we create and enroll. In general, this is realistic, in current
# securedrop usage it is way less
JOURNALISTS = 10
# How many ephemeral keys each journalist create, sign and auploads when required
ONETIMEKEYS = 30
# How may entries the server sends to each party when they try to fetch messages
# This basically must be more than the msssages in the database, otherwise we need
# to develop a mechanism to group messages adding some bits of metadata
MAX_MESSAGES = 500
# The base size of every parts in which attachment are splitted/padded to. This
# is not the actual size on disk, cause thet will be a bit more depending on
# the nacl SecretBox implementation
CHUNK = 512 * 1024


def add_journalist(journalist_key, journalist_sig, journalist_fetching_key, journalist_fetching_sig):
    journalist_uid = sha3_256(journalist_key.verify_key.encode()).hexdigest()
    journalist_key = journalist_key.verify_key.encode(Base64Encoder).decode("ascii")
    journalist_fetching_key = journalist_fetching_key.public_key.encode(Base64Encoder).decode("ascii")

    response = requests.post(f"http://{SERVER}/journalists", json={
                "journalist_key": journalist_key,
                "journalist_sig": journalist_sig,
                "journalist_fetching_key": journalist_fetching_key,
                "journalist_fetching_sig": journalist_fetching_sig
    })
    assert (response.status_code == 200)
    return journalist_uid


def get_journalists(intermediate_verifying_key):
    response = requests.get(f"http://{SERVER}/journalists")
    assert (response.status_code == 200)
    journalists = response.json()["journalists"]
    assert (len(journalists) == JOURNALISTS)
    for content in journalists:
        journalist_verifying_key = VerifyKey(content["journalist_key"], Base64Encoder)
        journalist_fetching_verifying_key = VerifyKey(content["journalist_fetching_key"], Base64Encoder)
        # pki.verify_key shall give an hard fault is a signature is off
        pki.verify_key_func(intermediate_verifying_key,
                            journalist_verifying_key,
                            None,
                            content["journalist_sig"])
        pki.verify_key_func(intermediate_verifying_key,
                            journalist_fetching_verifying_key,
                            None,
                            content["journalist_fetching_sig"])
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
                ephemeral_key_dict["journalist_fetching_key"] = journalist["journalist_fetching_key"]
                # add uids to a set
                checked_uids.add(journalist_uid)
                journalist_verifying_key = VerifyKey(journalist["journalist_key"], Base64Encoder)
        ephemeral_verifying_key = VerifyKey(ephemeral_key_dict["ephemeral_key"], Base64Encoder)
        # We rely again on verify_key raising an exception in case of failure
        pki.verify_key_func(journalist_verifying_key,
                            ephemeral_verifying_key,
                            None,
                            ephemeral_key_dict["ephemeral_sig"])
        ephemeral_keys_return.append(ephemeral_key_dict)
    # check that all keys are from different journalists
    assert (len(checked_uids) == JOURNALISTS)
    return ephemeral_keys_return


def build_message(fetching_public_key, encryption_public_key):
    fetching_public_key = PublicKey(fetching_public_key, Base64Encoder)
    encryption_public_key = PublicKey(encryption_public_key, Base64Encoder)

    message_secret_key = PrivateKey.generate()
    message_public_key = (message_secret_key.public_key.encode(Base64Encoder)).decode("ascii")

    # encrypt the message, we trust nacl safe defaults
    box = Box(message_secret_key, encryption_public_key)

    # generate the message gdh to send the server
    message_gdh = b64encode(Box(message_secret_key, fetching_public_key).shared_key())

    return message_public_key, message_gdh, box


def send_message(message_ciphertext, message_public_key, message_gdh):
    send_dict = {"message_ciphertext": message_ciphertext,
                 "message_public_key": message_public_key,
                 "message_gdh": message_gdh}

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


def fetch():
    response = requests.get(f"http://{SERVER}/fetch")
    assert (response.status_code == 200)
    return response.json()["messages"]


def get_message(message_id):
    response = requests.get(f"http://{SERVER}/message/{message_id}")
    assert (response.status_code == 200)
    assert ("message" in response.json())
    return response.json()["message"]


def delete_message(message_id):
    response = requests.delete(f"http://{SERVER}/message/{message_id}")
    assert (response.status_code == 200)
    return response.status_code == 200


def fetch_messages_id(fetching_key):
    potential_messages = fetch()

    messages = []

    for message in potential_messages:
        message_gdh = PublicKey(message["gdh"], Base64Encoder)
        message_client_box = Box(fetching_key, message_gdh)

        message_id = message_client_box.decrypt(message["enc"], Base64Encoder).decode('ascii')
        messages.append(message_id)



    if len(messages) > 0:
        return messages


def fetch_messages_content(messages_id):
    messages_list = []
    for message_id in messages_id:
        messages_list.append(get_message(message_id))
        return messages_list


def decrypt_message_ciphertext(private_key, message_public_key, message_ciphertext):
    private_key = PrivateKey(private_key)
    public_key = PublicKey(message_public_key, Base64Encoder)
    box = Box(private_key, public_key)
    try:
        message_plaintext = json.loads(box.decrypt(message_ciphertext, Base64Encoder).decode('ascii'))
        return message_plaintext
    except Exception:
        return False


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

            box = SecretBox(key)
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
