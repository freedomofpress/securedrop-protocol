import requests
import libs.pki
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

def simulation_get_source_private_key_from_server():
	response = requests.get(f"http://{SERVER}/simulation/get_source_private_key")
	if response.status_code == 404:
		return False
	else:
		return int(response.json()["source_private_key"])

def simulation_get_source_public_key_from_server():
	response = requests.get(f"http://{SERVER}/simulation/get_source_public_key")
	if response.status_code == 404:
		return False
	else:
		return int(response.json()["source_public_key"])

def simulation_set_source_private_key_in_server(privateKey):
	response = requests.post(f"http://{SERVER}/simulation/set_source_private_key", json={"source_private_key": privateKey})
	assert(response.status_code == 200)

def simulation_set_source_public_key_in_server(publicKey):
	response = requests.post(f"http://{SERVER}/simulation/set_source_public_key", json={"source_public_key": publicKey})
	assert(response.status_code == 200)

def get_message_challenges():
	response = requests.get(f"http://{SERVER}/get_message_challenges")
	assert(response.status_code == 200)
	return response.json()

def send_messages_challenges_responses(challenge_id, message_challenges_responses):
	message_challenges_responses_dict = {"message_challenges_responses": message_challenges_responses}
	response = requests.post(f"http://{SERVER}/send_message_challenges_responses/{challenge_id}", json=message_challenges_responses_dict)
	if response.status_code != 200:
		return False
	else:
		return response.json()

def main():
	if not simulation_get_source_private_key_from_server():
		print("[+] Generating a new keypair")
		k = generate_keypair()
		simulation_set_source_private_key_in_server(k.privateKey)
		simulation_set_source_public_key_in_server(k.publicKey)
	else:
		print("[+] Loading keypair")
		privateKey = simulation_get_source_private_key_from_server()
		k = load_keypair(privateKey)

	message_challenges_resp = get_messages_challenges()
	message_challenges = message_challenges_resp['message_challenges']
	challenge_id = message_challenges_resp['challenge_id']
	inv_source = pow(k.privateKey, -1, k.prime-1)
	
	message_challenges_responses = []

	for message_challenge in message_challenges:
		message_challenges_responses.append(pow(message_challenge, inv_source, k.prime))

	res = send_messages_challenges_responses(challenge_id, message_challenges_responses)
	print(res)

main()