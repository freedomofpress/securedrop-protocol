import requests
import pki
import nacl.secret
import nacl.utils
import json
import sys
from time import time
from secrets import token_bytes
from hashlib import sha3_256
from ecdsa import SigningKey, VerifyingKey, ECDH
from base64 import b64decode, b64encode

from commons import *

def generate_passphrase():
	return token_bytes(32)

# this function derives an EC keypair given the passphrase
# the prefix is useful for isolating key. A hash/kdf is used to generate the actual seeds
def derive_key(passphrase, key_isolation_prefix):
	key_seed = sha3_256(key_isolation_prefix.encode("ascii") + passphrase).digest()
	key_prng = pki.PRNG(key_seed[0:32])
	key = SigningKey.generate(curve=pki.CURVE, entropy=key_prng.deterministic_random)
	return key

def send_submission(intermediate_verifying_key, passphrase, message):
	# Get all the journalists, their keys, and the signatures of their keys from the server API
	# and verify the trust chain, otherwise the function will hard fail
	journalists = get_journalists(intermediate_verifying_key)
	
	# Get an ephemeral key for each journalist, check that the signatures are good and that
	# we have different journalists
	ephemeral_keys = get_ephemeral_keys(journalists)

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
		message_public_key, message_challenge, box = build_message(ephemeral_key_dict["journalist_key"], ephemeral_key_dict["ephemeral_key"])
		
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
						"attachments": [],
						# and respective keys
						"attachments_keys": [],
					   }

		message_ciphertext = b64encode(box.encrypt((json.dumps(message_dict)).ljust(1024).encode('ascii'))).decode("ascii")

		# Send the message to the server API using the generic /send endpoint
		send_message(message_ciphertext, message_public_key, message_challenge)

def fetch_messages_source(passphrase):
	challenge_key = derive_key(passphrase, "challenge_key-")
	messages_list = fetch_messages(challenge_key)
	return messages_list

def main():
	# Generate or load a passphrase
	if (len(sys.argv) == 1):
		passphrase = generate_passphrase()
		print(f"[+] Generating source passphrase: {passphrase.hex()}")

		intermediate_verifying_key = pki.verify_root_intermediate()
		message = "source message submission demo"
		send_submission(intermediate_verifying_key, passphrase, message)

	else:
		passphrase = bytes.fromhex(sys.argv[1])

		messages_list = fetch_messages_source(passphrase)
		source_key = derive_key(passphrase, "source_key-")

		for message in messages_list:
			# Decrypt every message building a shared encryption key using
			# the source long term key and the ephemeral per-message public key
			# This is the sad bit where, even if one of the two keys is ephemeral,
			# the other is not and thus no forward secrecy.
			plaintext_message = decrypt_message_ciphertext(source_key, message["message_public_key"], message["message_ciphertext"])
			print("---BEGIN JOURNALIST REPLY---")
			print(f"\t\tMessage: {plaintext_message['message']}")
			print(f"\t\tTimestamp: {plaintext_message['timestamp']}")
			print(f"\t\tJournalist UID: {plaintext_message['sender']}")
			print("---END JOURNALIST REPLY---")
main()