import pki
import requests
import sys
import ecdsa
import hashlib
from libs.DiffieHellman import DiffieHellman
from libs.linkable_ring_signature import ring_signature

SERVER = "127.0.0.1:5000"
DIR = "keys/"
JOURNALISTS = 10
ONETIMEKEYS = 30

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
	assert(len(sys.argv) == 2)
	journalist_id = int(sys.argv[1])
	assert(journalist_id >= 0 and journalist_id < JOURNALISTS)
	journalist_key = pki.load_and_verify_journalist_keypair(journalist_id)
	journalist_verifying_keys = pki.load_and_verify_journalist_verifying_keys()

	for key in range(ONETIMEKEYS):
		print(f"Generating {key}")
		message = "testtest"
		res = ring_signature(journalist_key,
					   journalist_verifying_keys.index(journalist_key.verifying_key),
					   message,
					   journalist_verifying_keys)
		print(res[1])


	# get source public key (got from the server per simulation, otherwise sealed in the initial source message)
	#source_public_key = simulation_get_source_public_key_from_server()
	#assert(source_public_key)
	#assert(send_message(source_public_key))


main()