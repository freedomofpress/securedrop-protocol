import pki
import requests
import sys
import ecdsa
import json
import nacl.secret
from base64 import b64decode, b64encode
from hashlib import sha3_256
from os import mkdir, listdir
from ecdsa import SigningKey, VerifyingKey, ECDH

from commons import *

SERVER = "127.0.0.1:5000"
DIR = "keys/"
JOURNALISTS = 10
ONETIMEKEYS = 30

def add_ephemeral_keys(journalist_key, journalist_id, journalist_uid):
	ephemeral_keys = []
	for key in range(ONETIMEKEYS):
		ephemeral_sig, ephemeral_key = pki.generate_ephemeral(journalist_key, journalist_id, journalist_uid)		
		ephemeral_keys.append({"ephemeral_key": b64encode(ephemeral_key.verifying_key.to_string()).decode("ascii"),
							   "ephemeral_sig": b64encode(ephemeral_sig).decode("ascii")})

	response = requests.post(f"http://{SERVER}/ephemeral_keys", json={"journalist_uid": journalist_uid,
																	  "ephemeral_keys": ephemeral_keys})

def load_ephemeral_keys(journalist_key, journalist_id, journalist_uid):
	ephemeral_keys = []
	key_file_list = listdir(f"{DIR}journalists/{journalist_uid}/")
	for file_name in key_file_list:
		if file_name.endswith('.key'):
			with open(f"{DIR}journalists/{journalist_uid}/{file_name}", "rb") as f:
				key = f.read()
			ephemeral_keys.append(SigningKey.from_pem(key))
	return ephemeral_keys

def decrypt_message_ciphertext(ephemeral_private_key, message_public_key, message_ciphertext):
	ecdh = ECDH(curve=pki.CURVE)
	ecdh.load_private_key(ephemeral_private_key)
	ecdh.load_received_public_key_bytes(b64decode(message_public_key))
	encryption_shared_secret = ecdh.generate_sharedsecret_bytes() 
	box = nacl.secret.SecretBox(encryption_shared_secret)
	try:
		message_plaintext = json.loads(box.decrypt(b64decode(message_ciphertext)).decode('ascii'))
		return message_plaintext
	except:
		return False

def main():
	assert(len(sys.argv) == 2)
	journalist_id = int(sys.argv[1])
	assert(journalist_id >= 0 and journalist_id < JOURNALISTS)
	journalist_sig, journalist_key = pki.load_and_verify_journalist_keypair(journalist_id)
	journalist_uid = add_journalist(journalist_key, journalist_sig)
	add_ephemeral_keys(journalist_key, journalist_id, journalist_uid)


	challenge_id, message_challenges = get_challenges()

	inv_secret = pki.ec_mod_inverse(journalist_key)
	inv_journalist = SigningKey.from_secret_exponent(inv_secret, curve=pki.CURVE)
	
	message_challenges_responses = []

	for message_challenge in message_challenges:
		#print(f"chall: {len(b64decode(message_challenge))}")
		message_challenges_response = VerifyingKey.from_public_point(pki.get_shared_secret(VerifyingKey.from_string(b64decode(message_challenge), curve=pki.CURVE), inv_journalist), curve=pki.CURVE)
		#print(f"resp: {len(message_challenges_response.to_string())}")
		message_challenges_responses.append(b64encode(message_challenges_response.to_string()).decode('ascii'))

	res = send_messages_challenges_responses(challenge_id, message_challenges_responses)
	messages_list = []
	if res:
		messages = res["messages"]
		print(f"[+] Fetched {len(messages)} messages :)")
		for message_id in messages:
			messages_list.append(get_message(message_id))
			#delete_message(message_id)
	else:
		print("[-] There are no messages to fetch.")

	#print(messages_list)
	ephemeral_keys = load_ephemeral_keys(journalist_key, journalist_id, journalist_uid)
	
	for message in messages_list:
		for ephemeral_key in ephemeral_keys:
			message_plaintext = decrypt_message_ciphertext(ephemeral_key, message["message_public_key"], message["message_ciphertext"])
			if message_plaintext:
				print(message_plaintext)
				break

main()