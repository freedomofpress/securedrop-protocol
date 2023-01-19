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

# used for deterministally generate keys based on the passphrase
class PRNG:
	def __init__(self, seed):
		assert(len(seed) == 32)
		self.total_size = 4096
		self.seed = seed
		self.status = 0
		self.data = nacl.utils.randombytes_deterministic(self.total_size, self.seed)

	def deterministic_random(self, size):
		if self.status + size >= self.total_size:
			raise RuntimeError("Ran out of buffered random values")
		return_data = self.data[self.status:self.status+size]
		self.status += size
		return return_data

def generate_passphrase():
	return token_bytes(32)

def main():
	# generate or load a passphrase
	if (len(sys.argv) == 1):
		passphrase = generate_passphrase()
	else:
		passphrase = bytes.fromhex(sys.argv[1])
	print(f"[+] Generating source passphrase: {passphrase.hex()}")
	message = "will this ever work?" 
	intermediate_verifying_key = pki.verify_root_intermediate()
	# get all the journalists, their keys, and the signatures of their keys from the server API
	# and verify the trust chain, otherwise the function will hard fail
	journalists = get_journalists(intermediate_verifying_key)
	# get on ephemeral key for each journalist, check that the signatures are good and that
	# we have different journalists
	ephemeral_keys = get_ephemeral_keys(journalists)

	# we deterministically derive the source long term keys from the passphrase
	# add prefix for key isolation
	source_key_seed = sha3_256(b"source_key-" + passphrase).digest()
	source_key_prng = PRNG(source_key_seed[0:32])

	# [SOURCE] LONG-TERM MESSAGE KEY
	source_key = SigningKey.generate(curve=pki.CURVE, entropy=source_key_prng.deterministic_random)

	challenge_key_seed = sha3_256(b"challenge_key-" + passphrase).digest()
	challenge_key_prng = PRNG(challenge_key_seed[0:32])

	# [SOURCE] LONG-TERM CHALLENGE KEY
	challenge_key = SigningKey.generate(curve=pki.CURVE, entropy=challenge_key_prng.deterministic_random)

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
						#"sender": source_id,
						"receiver": ephemeral_key_dict["journalist_uid"],
						# we could list the journalists involved in the conversation here
						# if the source choose not to pick everybody
						"group": [],
						"timestamp": int(time()),
						# we can add attachmenet pieces/id here
						"attachments": [],
						# and respective keys
						"attachments_keys": [],
					   }

		# we later use "MSGHDR" to test for proper decryption
		message_ciphertext = b64encode(box.encrypt(("MSGHDR" + json.dumps(message_dict)).ljust(1024).encode('ascii'))).decode("ascii")

		# send the message to the server API using the generic /send endpoint
		send_message(message_ciphertext, message_public_key, message_challenge)

main()