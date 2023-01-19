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

def get_challenges():
	response = requests.get(f"http://{SERVER}/get_challenges")
	assert(response.status_code == 200)
	return response.json()

def get_journalists(intermediate_verifying_key):
	response = requests.get(f"http://{SERVER}/journalists")
	assert(response.status_code == 200)
	journalists = response.json()["journalists"]
	assert(len(journalists) == JOURNALISTS)
	for content in journalists:
		journalist_verifying_key = VerifyingKey.from_string(b64decode(content["journalist_key"]), curve=pki.CURVE) 
		journalist_sig = pki.verify_key(intermediate_verifying_key, journalist_verifying_key, None, b64decode(content["journalist_sig"]))
	return journalists

def get_ephemeral_keys(journalists):
	response = requests.get(f"http://{SERVER}/ephemeral_keys")
	assert(response.status_code == 200)
	ephemeral_keys = response.json()["ephemeral_keys"]
	assert(len(ephemeral_keys) == JOURNALISTS)
	ephemeral_keys_return = []
	checked_uids = set()
	for ephemeral_key_dict in ephemeral_keys:
		journalist_uid = ephemeral_key_dict["journalist_uid"]
		for journalist in journalists:
			if journalist_uid == journalist["journalist_uid"]:
				ephemeral_key_dict["journalist_uid"] = journalist["journalist_uid"]
				ephemeral_key_dict["journalist_key"] = journalist["journalist_key"]
				# add uids to a set
				checked_uids.add(journalist_uid)
				journalist_verifying_key = VerifyingKey.from_string(b64decode(journalist["journalist_key"]), curve=pki.CURVE) 
		ephemeral_verifying_key = VerifyingKey.from_string(b64decode(ephemeral_key_dict["ephemeral_key"]), curve=pki.CURVE)
		ephemeral_sig = pki.verify_key(journalist_verifying_key, ephemeral_verifying_key, None, b64decode(ephemeral_key_dict["ephemeral_sig"]))
		ephemeral_keys_return.append(ephemeral_key_dict)
	# check that all keys are from different journalists
	assert(len(checked_uids) == JOURNALISTS)
	return ephemeral_keys_return

def send_message(message_ciphertext, message_public_key, message_challenge):
	send_dict = {"message_ciphertext": message_ciphertext,
				 "message_public_key": message_public_key,
				 "message_challenge": message_challenge
				}

	response = requests.post(f"http://{SERVER}/send", json=send_dict)
	if response.status_code != 200:
		return False
	else:
		return response.json()

def send_messages_challenges_responses(challenge_id, message_challenges_responses):
	message_challenges_responses_dict = {"message_challenges_responses": message_challenges_responses}
	response = requests.post(f"http://{SERVER}/send_responses/{challenge_id}", json=message_challenges_responses_dict)
	if response.status_code != 200:
		return False
	else:
		return response.json()

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
	journalists = get_journalists(intermediate_verifying_key)
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
		message_public_key = b64encode(message_key.to_string()).decode("ascii")
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

		message_challenge = b64encode(VerifyingKey.from_public_point(pki.get_shared_secret(VerifyingKey.from_string(journalist_long_term_key, curve=pki.CURVE), message_key), curve=pki.CURVE).to_string()).decode('ascii')

		message_dict = {"message": message,
						#"sender": source_id,
						"receiver": ephemeral_key_dict["journalist_uid"],
						"group": [],
						"timestamp": int(time()),
						"attachments": [],
						"attachments_keys": [],
						#"secret_challenge": secret_challenge
					   }

		# we later use "MSGHDR" to test for proper decryption
		message_ciphertext = b64encode(box.encrypt(("MSGHDR" + json.dumps(message_dict)).ljust(1024).encode('ascii'))).decode("ascii")

		send_message(message_ciphertext, message_public_key, message_challenge)

	'''if not simulation_get_source_private_key_from_server():
		print("[+] Generating a new keypair")
		k = generate_keypair()
		simulation_set_source_private_key_in_server(k.privateKey)
		simulation_set_source_public_key_in_server(k.publicKey)
	else:
		print("[+] Loading keypair")
		privateKey = simulation_get_source_private_key_from_server()
		k = load_keypair(privateKey)

	message_challenges_resp = get_challenges()
	message_challenges = message_challenges_resp['message_challenges']
	challenge_id = message_challenges_resp['challenge_id']
	inv_source = pow(k.privateKey, -1, k.prime-1)
	
	message_challenges_responses = []

	for message_challenge in message_challenges:
		message_challenges_responses.append(pow(message_challenge, inv_source, k.prime))

	res = send_messages_challenges_responses(challenge_id, message_challenges_responses)
	print(res)'''

main()