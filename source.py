import argparse
import json
from base64 import b64encode
from datetime import datetime
from hashlib import sha3_256
from secrets import token_bytes
from time import time

from ecdsa import SigningKey

import commons
import pki


def generate_passphrase():
    return token_bytes(32)


# this function derives an EC keypair given the passphrase
# the prefix is useful for isolating key. A hash/kdf is used to generate the actual seeds
def derive_key(passphrase, key_isolation_prefix):
    key_seed = sha3_256(key_isolation_prefix.encode("ascii") + passphrase).digest()
    key_prng = pki.PRNG(key_seed[0:32])
    key = SigningKey.generate(curve=commons.CURVE, entropy=key_prng.deterministic_random)
    return key


def send_submission(intermediate_verifying_key, passphrase, message, attachments):
    # Get all the journalists, their keys, and the signatures of their keys from the server API
    # and verify the trust chain, otherwise the function will hard fail
    journalists = commons.get_journalists(intermediate_verifying_key)

    # Get an ephemeral key for each journalist, check that the signatures are good and that
    # we have different journalists
    ephemeral_keys = commons.get_ephemeral_keys(journalists)

    # We deterministically derive the source long term keys from the passphrase
    # Add prefix for key isolation
    # [SOURCE] LONG-TERM MESSAGE KEY
    source_key = derive_key(passphrase, "source_key-")
    source_encryption_public_key = b64encode(source_key.verifying_key.to_string()).decode("ascii")

    # [SOURCE] LONG-TERM CHALLENGE KEY
    challenge_key = derive_key(passphrase, "challenge_key-")
    source_challenge_public_key = b64encode(challenge_key.verifying_key.to_string()).decode("ascii")

    # For every receiver (journalists), create a message
    for ephemeral_key_dict in ephemeral_keys:
        # This function builds the per-message keys and returns a nacl encrypting box
        message_public_key, message_challenge, box = commons.build_message(ephemeral_key_dict["journalist_chal_key"],
                                                                           ephemeral_key_dict["ephemeral_key"])

        # Same as on the journalist side: this structure is built by the clients
        # and thus potentially "untrusted"
        message_dict = {"message": message,
                        # do we want to sign messages? how do we attest source authoriship?
                        "source_challenge_public_key": source_challenge_public_key,
                        "source_encryption_public_key": source_encryption_public_key,
                        "receiver": ephemeral_key_dict["journalist_uid"],
                        # we could list the journalists involved in the conversation here
                        # if the source choose not to pick everybody
                        "group_members": [],
                        "timestamp": int(time()),
                        # we can add attachmenet pieces/id here
                        "attachments": attachments}

        message_ciphertext = b64encode(box.encrypt(
            (json.dumps(message_dict)).ljust(1024).encode('ascii'))
        ).decode("ascii")

        # Send the message to the server API using the generic /send endpoint
        commons.send_message(message_ciphertext, message_public_key, message_challenge)


def main(args):
    intermediate_verifying_key = pki.verify_root_intermediate()
    # Generate or load a passphrase
    if args.action == "submit":
        if not args.message:
            print("[-] Please specify a text message using -m")
            return -1
        passphrase = generate_passphrase()
        print(f"[+] New submission passphrase: {passphrase.hex()}")

        attachments = []
        if args.files:
            for file in args.files:
                attachment = commons.upload_attachment(file)
                if attachment:
                    attachments.append(attachment)
                else:
                    print(f"[-] Failed attaching {file}")
                    return -1

        send_submission(intermediate_verifying_key, passphrase, args.message, attachments)

    elif args.passphrase and args.action == "fetch":
        # Different from the journo side: we first parse the passphrase
        # and pass it to a different function where the challenge key will be derived
        passphrase = bytes.fromhex(args.passphrase)

        source_chal_key = derive_key(passphrase, "challenge_key-")

        messages_list = commons.fetch_messages_id(source_chal_key)

        if not messages_list:
            print("[-] The server did not return any message")
            return -1

        nmessages = len(messages_list)

        if nmessages > 0:
            print(f"[+] Found {nmessages} message(s)")
            for message_id in messages_list:
                print(f"\t{message_id}")
            print()
        else:
            print("[-] There are no messages")
            print()

    elif args.passphrase and args.action in ["read", "reply"]:
        if not args.id:
            print("[-] Please specify a message id using -i")
            return -1

        passphrase = bytes.fromhex(args.passphrase)
        message_id = args.id
        message = commons.get_message(message_id)
        source_key = derive_key(passphrase, "source_key-")
        message_plaintext = commons.decrypt_message_ciphertext(source_key,
                                                               message["message_public_key"],
                                                               message["message_ciphertext"])

        if args.action == "read" and message_plaintext:
            print(f"[+] Successfully decrypted message {message_id}")
            print()
            print(f"\tID: {message_id}")
            print(f"\tFrom: {message_plaintext['sender']}")
            print(f"\tDate: {datetime.fromtimestamp(message_plaintext['timestamp'])}")
            print(f"\tText: {message_plaintext['message']}")
            print()

        elif args.action == "reply":
            if not args.message:
                print("[-] Please specify a text message using -m")
                return -1
            send_submission(intermediate_verifying_key, passphrase, args.message, None)

    elif args.action == "delete":
        message_id = args.id
        commons.delete_message(message_id)
        print(f"[+] Message {message_id} deleted")
        print()

    else:
        print("[-] Invalid arguments combination")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--passphrase", help="Source passphrase if returning")
    parser.add_argument("-a", "--action", help="Action to perform", default="fetch", choices=["fetch", "read", "reply", "submit", "delete"], required=True)
    parser.add_argument("-i", "--id", help="Message id")
    parser.add_argument("-m", "--message", help="Plaintext message content for submissions or replies")
    parser.add_argument("-f", "--files", nargs="+", help="List of local files to submit")
    args = parser.parse_args()
    main(args)
