import requests
import pki
from ecdsa import SigningKey, VerifyingKey, Ed25519
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
	for ephemeral_key_dict in ephemeral_keys:
		journalist_uid = ephemeral_key_dict["journalist_uid"]
		for journalist in journalists:
			if journalist_uid == journalist["journalist_uid"]:
				ephemeral_key_dict["journalist_uid"] = journalist["journalist_uid"]
				ephemeral_key_dict["journalist_key"] = journalist["journalist_key"]
				journalist_verifying_key = VerifyingKey.from_string(b64decode(journalist["journalist_key"]), curve=pki.CURVE) 
		ephemeral_verifying_key = VerifyingKey.from_string(b64decode(ephemeral_key_dict["ephemeral_key"]), curve=pki.CURVE)
		ephemeral_sig = pki.verify_key(journalist_verifying_key, ephemeral_verifying_key, None, b64decode(ephemeral_key_dict["ephemeral_sig"]))
		ephemeral_keys_return.append(ephemeral_key_dict)
	return ephemeral_keys_return

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
		message_key = SigningKey.generate(curve=CURVE)
		encryption_shared_secret = 
		challenge_shared_secret = 

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