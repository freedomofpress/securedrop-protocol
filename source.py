import requests
import pki
import nacl.secret
import json
from ecdsa import SigningKey, VerifyingKey, ECDH
from base64 import b64decode, b64encode
from libs.DiffieHellman import DiffieHellman

SERVER = "127.0.0.1:5000"
DIR = "keys/"
JOURNALISTS = 10

def generate_keypair():
	k = DiffieHellman()
	return k

def load_keypair(privateKey):
	k = DiffieHellman(privateKey=privateKey)
	return k

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

def main():
	message = "will this ever work?" 
	intermediate_verifying_key = pki.verify_root_intermediate()
	journalists = get_journalists(intermediate_verifying_key)
	ephemeral_keys = get_ephemeral_keys(journalists)
	for ephemeral_key_dict in ephemeral_keys:

		ecdh = ECDH(curve=pki.CURVE)
		message_public_key = b64encode(ecdh.generate_private_key().to_string()).decode("ascii")
		ecdh.load_received_public_key_bytes(b64decode(ephemeral_key_dict["ephemeral_key"]))
		encryption_shared_secret = ecdh.generate_sharedsecret_bytes() 

		ecdh.load_received_public_key_bytes(b64decode(ephemeral_key_dict["journalist_key"]))
		challenge_shared_secret = ecdh.generate_sharedsecret_bytes()

		box = nacl.secret.SecretBox(encryption_shared_secret)

		message_dict = {"message": message,
						"sender": "a source, maybe a one way func of the passphrase",
						"receiver": ephemeral_key_dict["journalist_uid"],
						"date": "a date here",
						"attachments": [],
						"attachments_keys": []
					   }

		message_ciphertext = b64encode(box.encrypt(json.dumps(message_dict).ljust(1024).encode('ascii'))).decode("ascii")
		message_challenge = "bogus"
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