import argparse
import json
from base64 import b64encode
from datetime import datetime
from hashlib import sha3_256
from os import listdir, mkdir, path
from time import time
from secrets import token_hex

import nacl.secret
import requests
from ecdsa import SigningKey

import commons
import journalist_db
import pki


def add_ephemeral_keys(journalist_key, journalist_id, journalist_uid):
    ephemeral_keys = []
    for key in range(commons.ONETIMEKEYS):
        # Generate an ephemeral key, sign it and load the signature
        ephemeral_sig, ephemeral_key = pki.generate_ephemeral(journalist_key, journalist_id, journalist_uid)
        ephemeral_keys.append({"ephemeral_key": b64encode(ephemeral_key.verifying_key.to_string()).decode("ascii"),
                               "ephemeral_sig": b64encode(ephemeral_sig).decode("ascii")})

    # Send both to server, the server veifies the signature and the trust chain prior ro storing/publishing
    response = requests.post(f"http://{commons.SERVER}/ephemeral_keys", json={"journalist_uid": journalist_uid,
                                                                              "ephemeral_keys": ephemeral_keys})

    return (response.status_code == 200)


# Load the journalist ephemeral keys from the journalist key dirrectory.
# On an actual implementation this would more likely be a sqlite (or sqlcipher)
# database.
def load_ephemeral_keys(journalist_key, journalist_id, journalist_uid):
    ephemeral_keys = []
    key_file_list = listdir(f"{commons.DIR}journalists/{journalist_uid}/")
    for file_name in key_file_list:
        if file_name.endswith('.key'):
            with open(f"{commons.DIR}journalists/{journalist_uid}/{file_name}", "rb") as f:
                key = f.read()
            ephemeral_keys.append(SigningKey.from_pem(key))
    return ephemeral_keys


def add_file_tokens(journalist_key, journalist_uid):
    file_tokens = []
    # Every message will use up at least one token, so we'll generate more than commons.ONETIMEKEYS
    # to allow sources to add multiple attachments without running low on tokens
    for _ in range(commons.ONETIMEKEYS * 10):
        file_tokens.append((token_hex(32), token_hex(32)))

    file_tokens = json.dumps(file_tokens)
    file_tokens_dir = f"{commons.DIR}journalists/file_tokens/"
    try:
        mkdir(file_tokens_dir)
    except Exception:
        pass
    with open(f"{file_tokens_dir}{token_hex(32)}.json", "w") as f:
        f.write(file_tokens)

    sig = pki.sign(journalist_key, file_tokens.encode("ascii"))

    response = requests.post(f"http://{commons.SERVER}/file_tokens", json={
        "journalist_uid": journalist_uid,
        "sig": b64encode(sig).decode("ascii"),
        "file_tokens": file_tokens,
    })

    return (response.status_code == 200)


def load_file_tokens():
    pairs = []
    for file_name in listdir(f"{commons.DIR}journalists/file_tokens/"):
        pairs.extend(json.load(open(f"{commons.DIR}journalists/file_tokens/{file_name}")))
    return dict(pairs)


# Try all the ephemeral keys to build an encryption shared secret to decrypt a message.
# This is inefficient, but on an actual implementation we would discard already used keys
def decrypt_message(ephemeral_keys, message):
    for ephemeral_key in ephemeral_keys:
        message_plaintext = commons.decrypt_message_asymmetric(
            ephemeral_key, message["message_public_key"],
            message["message_ciphertext"])
        if message_plaintext:
            return message_plaintext


def journalist_reply(message, reply, journalist_uid, file_tokens):
    # This function builds the per-message keys and returns a nacl encrypting box
    message_public_key, message_challenge, box = commons.build_message(
        message["source_challenge_public_key"],
        message["source_encryption_public_key"])

    # The actual message struct varies depending on the sending party.
    # Still it is client controlled, so in each client we shall watch out a bit.
    message_dict = {"message": reply,
                    # do we want to sign messages? how do we attest source authoriship?
                    "sender": journalist_uid,
                    # "receiver": "source_id_placeholder",
                    # we could list the journalists involved in the conversation here
                    # if the source choose not to pick everybody
                    "group_members": [],
                    "timestamp": int(time())}

    # in a reply, we need to let the source know what the file_name is so it can access the
    # full message and delete it at its leisure
    file_id, key = commons.upload_message(json.dumps(message_dict))
    file_name = file_tokens[file_id]

    message_ciphertext = b64encode(box.encrypt(
        (json.dumps({"file_name": file_name, "key": key})).encode('ascii'))
    ).decode("ascii")

    # Send the message to the server API using the generic /send endpoint
    commons.send_message(message_ciphertext, message_public_key, message_challenge)


def main(args):
    # Get and check the journalist number we are impersonating
    journalist_id = args.journalist
    assert (journalist_id >= 0 and journalist_id < commons.JOURNALISTS)

    journalist_uid, journalist_sig, journalist_key, journalist_chal_sig, journalist_chal_key = pki.load_and_verify_journalist_keypair(journalist_id)
    jdb = journalist_db.JournalistDatabase('files/.jdb.sqlite3')

    if args.action == "upload_keys":
        journalist_uid = commons.add_journalist(journalist_key, journalist_sig, journalist_chal_key, journalist_chal_sig)

        # Generate and upload a bunch (30) of ephemeral keys
        add_ephemeral_keys(journalist_key, journalist_id, journalist_uid)

    elif args.action == "upload_file_tokens":
        # Generate and upload signed file tokens to be used by the server to hide file_ids from sources
        add_file_tokens(journalist_key, journalist_uid)

    elif args.action == "fetch":
        # Check if there are messages
        messages_list = commons.fetch_messages_id(journalist_chal_key)

        try:
            nmessages = len(messages_list)
        except Exception:
            nmessages = 0

        if nmessages > 0:
            print(f"[+] Found {nmessages} message(s)")
            for message_id in messages_list:
                print(f"\t{message_id}")
            print()
        else:
            print("[-] There are no messages")
            print()

    elif args.action == "read":
        message_id = args.id
        message = commons.get_message(message_id)
        ephemeral_keys = load_ephemeral_keys(journalist_key, journalist_id, journalist_uid)
        # Get the encrypted file_id and decryption key of the message
        message_plaintext = decrypt_message(ephemeral_keys, message)

        # Fetch and decrypt the actual message, that was stored as an attachment
        key = message_plaintext['key']
        file_tokens = load_file_tokens()
        file_name = file_tokens[message_plaintext['file_id']]
        encrypted_message_content = commons.get_file(file_name)
        message_plaintext = commons.decrypt_message_symmetric(encrypted_message_content, bytes.fromhex(key))

        if message_plaintext:
            # Create a download folder if we have attachments
            if (message_plaintext["attachments"] and
               len(message_plaintext["attachments"]) > 0):
                try:
                    mkdir(commons.DOWNLOADS)
                except Exception:
                    pass
            else:
                message_plaintext["attachments"] = []

            sender = sha3_256(message_plaintext['source_encryption_public_key'].encode("ascii")).hexdigest()
            print(f"[+] Successfully decrypted message {message_id}")
            print()
            print(f"\tID: {message_id}")
            print(f"\tFrom: {sender}")
            print(f"\tDate: {datetime.fromtimestamp(message_plaintext['timestamp'])}")
            for attachment in message_plaintext["attachments"]:
                print(f"\tAttachment: name={attachment['name']};size={attachment['size']};parts_count={attachment['parts_count']}")
                attachment_name = path.basename(attachment['name'])
                attachment_size = attachment['size']
                with open(f"{commons.DOWNLOADS}{int(time())}_{attachment_name}", "wb") as f:
                    part_number = 0
                    written_size = 0
                    while written_size < attachment_size:
                        for part in attachment["parts"]:
                            if part["number"] == part_number:
                                part_key = bytes.fromhex(part['key'])
                                encrypted_part = commons.get_file(part["id"])
                                written_size += part["size"]
                                box = nacl.secret.SecretBox(part_key)
                                f.write(box.decrypt(encrypted_part)[0:part["size"]])
                                part_number += 1

            print(f"\tText: {message_plaintext['message']}")
            print()
            jdb.insert_message(sender, datetime.fromtimestamp(message_plaintext['timestamp']), message_plaintext['message'])

    elif args.action == "thread":
        sender = args.thread
        messages = jdb.select_messages(sender)
        for message in messages:
            print(f'[{message[0]}]: {message[1]}')

    elif args.action == "reply":
        message_id = args.id
        message = commons.get_message(message_id)
        ephemeral_keys = load_ephemeral_keys(journalist_key, journalist_id, journalist_uid)
        envelope_plaintext = decrypt_message(ephemeral_keys, message)
        # journalists must map the file_id to file_name, as the source cannot tell us the latter
        file_tokens = load_file_tokens()
        file_name = file_tokens[envelope_plaintext['file_id']]
        message_ciphertext = commons.get_file(file_name)
        message_symmetric_key = bytes.fromhex(envelope_plaintext['key'])
        message_plaintext = commons.decrypt_message_symmetric(message_ciphertext,
                                                              message_symmetric_key)
        journalist_reply(message_plaintext, args.message, journalist_uid, file_tokens)

    elif args.action == "delete":
        message_id = args.id
        commons.delete_message(message_id)
        print(f"[+] Message {message_id} deleted")
        print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-j", "--journalist", help="Journalist number", type=int, choices=range(0, commons.JOURNALISTS), metavar=f"[0, {commons.JOURNALISTS - 1}]", required=True)
    parser.add_argument("-a", "--action", help="Action to perform", default="fetch", choices=["upload_keys", "upload_file_tokens", "fetch", "read", "reply", "delete", "thread"])
    parser.add_argument("-i", "--id", help="Message id")
    parser.add_argument("-t", "--thread", help="Thread id")
    parser.add_argument("-m", "--message", help="Plaintext message content for replies")
    args = parser.parse_args()
    main(args)
