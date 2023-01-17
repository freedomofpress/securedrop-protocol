import json
import pki
from hashlib import sha3_256
from ecdsa import SigningKey, VerifyingKey, Ed25519
from libs.DiffieHellman import DiffieHellman
from secrets import token_hex
from redis import Redis
from flask import Flask, request
from base64 import b64decode, b64encode

SERVER = "127.0.0.1:5000"
DIR = "keys/"
JOURNALISTS = 10
SERVER_JOURNALISTS_SHARED_SECRET = "63f9f34d01987f51ebab1e7408b8e7cf8c1e58444d2ab89bd2df98c9d16e0a14"

# bootstrap keys
intermediate_verifying_key = pki.verify_root_intermediate()

redis = Redis()
app = Flask(__name__)

@app.route("/")
def index():
    return {"status": "OK"}, 200

@app.route("/journalists", methods=["POST"])
def add_journalist():
	content = request.json
	try:
		assert("journalist_key" in content)
		assert("journalist_sig" in content)
	except:
		return {"status": "KO"}, 400

	journalist_verifying_key = VerifyingKey.from_string(b64decode(content["journalist_key"]), curve=pki.CURVE)
	try:
		journalist_sig = pki.verify_key(intermediate_verifying_key, journalist_verifying_key, None, b64decode(content["journalist_sig"]))
	except:
		return {"status": "KO"}, 400
	journalist_uid = sha3_256(journalist_verifying_key.to_string()).hexdigest()
	redis.sadd("journalists", json.dumps({"journalist_uid": journalist_uid,
										  "journalist_key": b64encode(journalist_verifying_key.to_string()).decode("ascii"),
										  "journalist_sig": b64encode(journalist_sig).decode("ascii")}))
	return {"status": "OK"}, 200

@app.route("/journalists", methods=["GET"])
def get_journalists():
	journalists_list = []
	journalists = redis.smembers("journalists")
	for journalist_json in journalists:
		journalists_list.append(json.loads(journalist_json.decode("ascii")))
	return {"status": "OK", "count": len(journalists), "journalists": journalists_list}, 200

@app.route("/ephemeral_keys", methods=["POST"])
def add_ephemeral_keys():
	content = request.json
	try:
		assert("journalist_uid" in content)
		assert("ephemeral_keys" in content)
	except:
		return {"status": "KO"}, 400

	journalist_uid = content["journalist_uid"]
	journalists = redis.smembers("journalists")
	
	for journalist in journalists:
		journalist_dict = json.loads(journalist.decode("ascii"))
		if journalist_dict["journalist_uid"] == journalist_uid:
			journalist_verifying_key = VerifyingKey.from_string(b64decode(journalist_dict["journalist_key"]), curve=pki.CURVE)
	ephemeral_keys = content["ephemeral_keys"]
	
	for ephemeral_key_dict in ephemeral_keys:
		ephemeral_key = b64decode(ephemeral_key_dict["ephemeral_key"])
		ephemeral_key_verifying_key = VerifyingKey.from_string(ephemeral_key, curve=pki.CURVE)
		ephemeral_sig = b64decode(ephemeral_key_dict["ephemeral_sig"])
		ephemeral_sig = pki.verify_key(journalist_verifying_key, ephemeral_key_verifying_key, None, ephemeral_sig)
		redis.sadd(f"journalist:{journalist_uid}", json.dumps({"ephemeral_key": b64encode(ephemeral_key_verifying_key.to_string()).decode("ascii"),
															   "ephemeral_sig": b64encode(ephemeral_sig).decode("ascii")}))

	return {"status": "OK"}, 200

@app.route("/ephemeral_keys", methods=["GET"])
def get_ephemeral_keys():
	journalists = redis.smembers("journalists")
	ephemeral_keys = []

	for journalist in journalists:
		journalist_dict = json.loads(journalist.decode("ascii"))
		journalist_uid = journalist_dict["journalist_uid"]
		ephemeral_key_dict = json.loads(redis.spop(f"journalist:{journalist_uid}").decode("ascii"))
		ephemeral_key_dict["journalist_uid"] = journalist_uid
		ephemeral_keys.append(ephemeral_key_dict)

	return {"status": "OK", "count": len(ephemeral_keys), "ephemeral_keys": ephemeral_keys}, 200

@app.route("/get_root_key", methods=["GET"])
def get_root_key():

	return {"status": "OK"}, 200

@app.route("/get_intermediate_key", methods=["GET"])
def get_intermediate_key():

	return {"status": "OK"}, 200


@app.route("/send", methods=["POST"])
def send():
	content = request.json
	try:
		assert("message" in content)
		assert("message_public_key" in content)
		assert("message_challenge" in content)
	except:
		return {"status": "KO"}, 400
	message_dict = {
		# encrypted message
		"message": request.json["message"],
		# gj, public key part of the keypar generated by the sending journalist for every message
		"message_public_key": request.json["message_public_key"],
		# gkj, public part computer using the source public key and the per message secret key
		"message_challenge": request.json["message_challenge"]
	}
	# save the journalist to source reply in redis
	redis.set(f"message:{token_hex(32)}", json.dumps(message_dict))
	return {"status": "OK"}, 200

@app.route("/get_challenges", methods=["GET"])
def get_messages_challenge():
	s = DiffieHellman()
	# generate a challenge id
	challenge_id = token_hex(32)
	# save it in redis as an expiring key
	redis.setex(f"challenge:{challenge_id}", 120, s.privateKey)
	messages_challenge = []
	# retrieve all the message keys
	message_keys = redis.keys("message:*")
	for message_key in message_keys:
		# retrieve the message and load the json
		message_dict = json.loads(redis.get(message_key).decode('ascii'))
		# calculate the "gkjs" challenge
		messages_challenge.append(pow(message_dict["message_challenge"], s.privateKey, s.prime))

	# return all the message challenges
	# padding to hide the number of meesages to be added later
	response_dict = {"status": "OK", "challenge_id": challenge_id, "message_challenges": messages_challenge}
	return response_dict, 200

@app.route("/send_responses/<challenge_id>", methods=["POST"])
def send_message_challenges_response(challenge_id):
	# retrieve the challenge secret key from the challenge id in redis
	privateKey = redis.get(f"challenge:{challenge_id}")
	if privateKey is not None:
		privateKey = int(privateKey.decode('ascii'))
	else:
		return {"status": "KO"}, 400

	# load the secret key and derive the public key
	s = DiffieHellman(privateKey=privateKey)
	try:
		assert("message_challenges_responses" in request.json)
	except:
		return {"status": "KO"}, 400

	# calculate the inverse of the per request server key
	inv_server = pow(s.privateKey, -1, s.prime - 1)

	# fetch all the messages again from redis
	message_keys = redis.keys("message:*")
	messages = []
	for message_key in message_keys:
		# retrieve the message and load the json
		messages.append({"message_id": message_key[8:].decode('ascii'), "message_public_key": json.loads(redis.get(message_key).decode('ascii'))["message_public_key"]})

	# check all the challenges responses
	potential_messages_public_keys = []
	for message_challenge_response in request.json["message_challenges_responses"]:
		potential_messages_public_keys.append(pow(message_challenge_response, inv_server, s.prime))

	# check if any public key in the computed challenge/responses matches any message and return them
	valid_messages = []
	for message in messages:
		for potential_messages_public_key in potential_messages_public_keys:
			if potential_messages_public_key == message["message_public_key"]:
				valid_messages.append(message["message_id"])
	if len(valid_messages) > 0:
		return {"status": "OK", "messages": valid_messages}, 200
	return "SAAAAAD", 404


