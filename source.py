import argparse
import json
from datetime import datetime
from secrets import token_bytes
from time import time

from nacl.encoding import Base64Encoder, RawEncoder
from nacl.hash import blake2b
from nacl.public import PrivateKey

import commons
import pki


def generate_passphrase():
    return token_bytes(32)


# this function derives an EC keypair given the passphrase
# the prefix is useful for isolating the key. A hash/kdf is used to generate the actual seeds
def derive_key(passphrase, key_isolation_prefix):
    key_seed = blake2b(passphrase, salt=key_isolation_prefix.encode("ascii"), encoder=RawEncoder)
    key = PrivateKey(key_seed)
    return key


def send_submission(intermediate_verifying_key, passphrase, message, attachments):
    # Get all the journalists, their keys, and the signatures of their keys from the server API
    # and verify the trust chain, otherwise the function will raise an exception
    journalists = commons.get_journalists(intermediate_verifying_key)

    # Get an ephemeral key for each journalist, check that the signatures are good and that
    # we have different journalists
    ephemeral_keys = commons.get_ephemeral_keys(journalists)

    # We deterministically derive the source long term keys from the passphrase
    # Add prefix for key isolation
    # [SOURCE] LONG-TERM MESSAGE KEY
    encryption_key = derive_key(passphrase, "encryption_key-")
    source_encryption_public_key = encryption_key.public_key.encode(Base64Encoder).decode("ascii")

    # [SOURCE] LONG-TERM CHALLENGE KEY
    fetching_key = derive_key(passphrase, "fetching_key-")
    source_fetching_public_key = fetching_key.public_key.encode(Base64Encoder).decode("ascii")

    # For every receiver (journalists), create a message
    for ephemeral_key_dict in ephemeral_keys:
        # This function builds the per-message keys and returns a nacl encrypting box
        message_public_key, message_gdh, box = commons.build_message(ephemeral_key_dict["journalist_fetching_key"],
                                                                     ephemeral_key_dict["ephemeral_key"])

        # Same as on the journalist side: this structure is built by the clients
        # and thus potentially "untrusted"
        message_dict = {"message": message,
                        # do we want to sign messages? how do we attest source authorship?
                        "source_fetching_public_key": source_fetching_public_key,
                        "source_encryption_public_key": source_encryption_public_key,
                        "receiver": ephemeral_key_dict["journalist_key"],
                        # we could list the journalists involved in the conversation here
                        # if the source choose not to pick everybody
                        "group_members": [],
                        "timestamp": int(time()),
                        # we can add attachmenet pieces/id here
                        "attachments": attachments}

        message_ciphertext = box.encrypt(
            (json.dumps(message_dict)).ljust(1024).encode('ascii'), encoder=Base64Encoder).decode("ascii")

        # Send the message to the server API using the generic /send endpoint
        commons.send_message(message_ciphertext, message_public_key, message_gdh)


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
        # Different from the journalist side: we first parse the passphrase
        # and pass it to a different function where the fetching key will be derived
        passphrase = bytes.fromhex(args.passphrase)

        source_fetching_key = derive_key(passphrase, "fetching_key-")

        messages_list = commons.fetch_messages_id(source_fetching_key)

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

    elif args.passphrase and args.action == "read":
        if not args.id:
            print("[-] Please specify a message id using -i")
            return -1

        passphrase = bytes.fromhex(args.passphrase)
        source_key = derive_key(passphrase, "encryption_key-")
        message_id = args.id
        message = commons.get_message(message_id)
        message_plaintext = commons.decrypt_message_ciphertext(source_key,
                                                               message["message_public_key"],
                                                               message["message_ciphertext"])

        if message_plaintext:
            print(f"[+] Successfully decrypted message {message_id}")
            print()
            print(f"\tID: {message_id}")
            print(f"\tFrom: {message_plaintext['sender']}")
            print(f"\tDate: {datetime.fromtimestamp(message_plaintext['timestamp'])}")
            print(f"\tText: {message_plaintext['message']}")
            print()

    elif args.passphrase and args.action == "reply":
        passphrase = bytes.fromhex(args.passphrase)
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
