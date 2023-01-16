import requests
from libs.DiffieHellman import DiffieHellman

SERVER = "127.0.0.1:5000"

def generate_keypair():
	k = DiffieHellman()
	return k

def simulation_get_source_public_key_from_server():
	response = requests.get(f"http://{SERVER}/simulation/get_source_public_key")
	if response.status_code == 404:
		return False
	else:
		return int(response.json()["source_public_key"])

def send_message(source_public_key):
	j = generate_keypair()
	# this public key is unique per message
	message_public_key = j.publicKey
	message_challenge = pow(source_public_key, j.privateKey, j.prime)
	
	response = requests.post(f"http://{SERVER}/send_j2s_message", json={"message": "placeholder",
															 "message_public_key": message_public_key,
															 "message_challenge": message_challenge})	
	return (response.status_code == 200)

def main():
	# get source public key (got from the server per simulation, otherwise sealed in the initial source message)
	source_public_key = simulation_get_source_public_key_from_server()
	assert(source_public_key)
	assert(send_message(source_public_key))


main()