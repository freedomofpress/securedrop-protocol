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

SERVER = "127.0.0.1:5000"
DIR = "keys/"
JOURNALISTS = 10

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
	# get all the journalists, their keys, and the signatures of their keys from the server API
	# and verify the trust chain, otherwise the function will hard fail
	journalists = get_journalists(intermediate_verifying_key)
	# get on ephemeral key for each journalist, check that the signatures are good and that
	# we have different journalists
	ephemeral_keys = get_ephemeral_keys(journalists)

	# we deterministically derive the source long term keys from the passphrase
	# add prefix for key isolation
	# [SOURCE] LONG-TERM MESSAGE KEY
	source_key = derive_key(passphrase, "source_key-")
	source_encryption_public_key = b64encode(source_key.verifying_key.to_string()).decode("ascii") 

	# [SOURCE] LONG-TERM CHALLENGE KEY
	challenge_key = derive_key(passphrase, "challenge_key-")
	source_challenge_public_key = b64encode(challenge_key.verifying_key.to_string()).decode("ascii") 

	# for every receiver (journalists), create a message
	for ephemeral_key_dict in ephemeral_keys:

		ecdh = ECDH(curve=pki.CURVE)
		# [SOURCE] PERMESSAGE-EPHEMERAL KEY (private)
		message_key = SigningKey.generate(curve=pki.CURVE)
		message_public_key = b64encode(message_key.verifying_key.to_string()).decode("ascii")
		# load the private key to generate the shared secret
		ecdh.load_private_key(message_key)

		# [JOURNALIST] PERMESSAGE-EPHEMERAL KEY (public)
		ecdh.load_received_public_key_bytes(b64decode(ephemeral_key_dict["ephemeral_key"]))
		# generate the secret for encrypting the secret with the source_ephemeral+journo_ephemeral
		# so that we have forward secrecy
		encryption_shared_secret = ecdh.generate_sharedsecret_bytes() 

		# encrypt the message, we trust nacl safe defaults
		box = nacl.secret.SecretBox(encryption_shared_secret)

		# generate the shared secret for the challenge/response using
		# source_ephemeral+journo_longterm
		# [JOURNALIST] LONG-TERM CHALLENGE KEY
		journalist_long_term_key = b64decode(ephemeral_key_dict["journalist_key"])

		# generate the message challenge to send the server
		message_challenge = b64encode(VerifyingKey.from_public_point(pki.get_shared_secret(VerifyingKey.from_string(journalist_long_term_key, curve=pki.CURVE), message_key), curve=pki.CURVE).to_string()).decode('ascii')

		message_dict = {"message": message,
						# do we want to sign messages? how do we attest source authoriship?
						"source_challenge_public_key": source_encryption_public_key,
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

		# we later use "MSGHDR" to test for proper decryption
		message_ciphertext = b64encode(box.encrypt((json.dumps(message_dict)).ljust(1024).encode('ascii'))).decode("ascii")

		# send the message to the server API using the generic /send endpoint
		send_message(message_ciphertext, message_public_key, message_challenge)

def fetch_messages(passphrase):
	pass

def main():
	# generate or load a passphrase
	if (len(sys.argv) == 1):
		passphrase = generate_passphrase()
	else:
		passphrase = bytes.fromhex(sys.argv[1])
	print(f"[+] Generating source passphrase: {passphrase.hex()}")

	intermediate_verifying_key = pki.verify_root_intermediate()
	message = "wewelolol"
	send_submission(intermediate_verifying_key, passphrase, message)


main()