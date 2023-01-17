import pki
import requests
import sys
import ecdsa
from base64 import b64decode, b64encode
from hashlib import sha3_256
from os import mkdir
from libs.DiffieHellman import DiffieHellman
from ecdsa import SigningKey, VerifyingKey, Ed25519

#from libs.linkable_ring_signature import ring_signature

SERVER = "127.0.0.1:5000"
DIR = "keys/"
JOURNALISTS = 10
ONETIMEKEYS = 30
SERVER_JOURNALISTS_SHARED_SECRET = "63f9f34d01987f51ebab1e7408b8e7cf8c1e58444d2ab89bd2df98c9d16e0a14"

def send_message(source_public_key):
	j = generate_keypair()
	# this public key is unique per message
	message_public_key = j.publicKey
	message_challenge = pow(source_public_key, j.privateKey, j.prime)
	
	response = requests.post(f"http://{SERVER}/send", json={"message": "placeholder",
															"message_public_key": message_public_key,
															"message_challenge": message_challenge})	
	return (response.status_code == 200)

def add_journalist(journalist_key, journalist_sig):
	journalist_uid = sha3_256(journalist_key.verifying_key.to_string()).hexdigest()

	response = requests.post(f"http://{SERVER}/journalists", json={"journalist_key": b64encode(journalist_key.verifying_key.to_string()).decode("ascii"),
															 	    "journalist_sig": b64encode(journalist_sig).decode("ascii")})
	return journalist_uid

def add_ephemeral_keys(journalist_key, journalist_id, journalist_uid):
	ephemeral_keys = []
	for key in range(ONETIMEKEYS):
		ephemeral_sig, ephemeral_key = pki.generate_ephemeral(journalist_key, journalist_id)		
		ephemeral_keys.append({"ephemeral_key": b64encode(ephemeral_key.verifying_key.to_string()).decode("ascii"),
							   "ephemeral_sig": b64encode(ephemeral_sig).decode("ascii")})

	response = requests.post(f"http://{SERVER}/ephemeral_keys", json={"journalist_uid": journalist_uid,
																		  "ephemeral_keys": ephemeral_keys})

def main():
	assert(len(sys.argv) == 2)
	journalist_id = int(sys.argv[1])
	assert(journalist_id >= 0 and journalist_id < JOURNALISTS)
	journalist_sig, journalist_key = pki.load_and_verify_journalist_keypair(journalist_id)
	journalist_uid = add_journalist(journalist_key, journalist_sig)
	add_ephemeral_keys(journalist_key, journalist_id, journalist_uid)


	# get source public key (got from the server per simulation, otherwise sealed in the initial source message)
	#source_public_key = simulation_get_source_public_key_from_server()
	#assert(source_public_key)
	#assert(send_message(source_public_key))

		# Ring signature vartion
		# As we adapted the lib, lets keep the code
		#message = "testtest"
		#res = ring_signature(journalist_key,
		#			   journalist_verifying_keys.index(journalist_key.verifying_key),
		#			   message,
		#			   journalist_verifying_keys)
		#print(res[1])


main()