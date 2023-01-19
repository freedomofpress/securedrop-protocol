import pki
import requests
from base64 import b64decode, b64encode
from ecdsa import SigningKey, VerifyingKey
from hashlib import sha3_256

SERVER = "127.0.0.1:5000"
JOURNALISTS = 10

def add_journalist(journalist_key, journalist_sig):
	journalist_uid = sha3_256(journalist_key.verifying_key.to_string()).hexdigest()

	response = requests.post(f"http://{SERVER}/journalists", json={"journalist_key": b64encode(journalist_key.verifying_key.to_string()).decode("ascii"),
															 	    "journalist_sig": b64encode(journalist_sig).decode("ascii")})
	return journalist_uid

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

	response = requests.post(f"http://{SERVER}/message", json=send_dict)
	if response.status_code != 200:
		return False
	else:
		return response.json()

def get_challenges():
	response = requests.get(f"http://{SERVER}/get_challenges")
	assert(response.status_code == 200)
	return response.json()["challenge_id"], response.json()["message_challenges"]

def send_messages_challenges_responses(challenge_id, message_challenges_responses):
	message_challenges_responses_dict = {"message_challenges_responses": message_challenges_responses}
	response = requests.post(f"http://{SERVER}/send_responses/{challenge_id}", json=message_challenges_responses_dict)
	if response.status_code != 200:
		return False
	else:
		return response.json()

def get_message(message_id):
	response = requests.get(f"http://{SERVER}/message/{message_id}")
	assert(response.status_code == 200)
	assert("message" in response.json())
	return response.json()["message"]

def delete_message(message_id):
	requests.delete(f"http://{SERVER}/message/{message_id}")
	assert(response.status_code == 200)
	return response.status_code == 200