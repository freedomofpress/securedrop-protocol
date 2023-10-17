import json
from base64 import b64decode, b64encode
from hashlib import sha3_256
from os import mkdir, remove
from random import uniform
from secrets import token_bytes, token_hex
from time import sleep

import nacl.secret
from ecdsa import ECDH, SigningKey, VerifyingKey
from flask import Flask, request, send_file
from redis import Redis

import commons
import pki

# bootstrap keys
intermediate_verifying_key = pki.verify_root_intermediate()

redis = Redis()
app = Flask(__name__)

try:
    mkdir(f"{commons.UPLOADS}")
except Exception:
    pass


@app.route("/")
def index():
    return {"status": "OK"}, 200


@app.route("/journalists", methods=["POST"])
def add_journalist():
    content = request.json
    print(content)
    try:
        assert ("journalist_key" in content)
        assert ("journalist_sig" in content)
        assert ("journalist_fetching_key" in content)
        assert ("journalist_fetching_sig" in content)
    except Exception:
        return {"status": "KO"}, 400

    journalist_verifying_key = pki.public_b642key(content["journalist_key"])
    journalist_fetching_verifying_key = pki.public_b642key(content["journalist_fetching_key"])
    try:
        journalist_sig = pki.verify_key(intermediate_verifying_key,
                                        journalist_verifying_key,
                                        None,
                                        b64decode(content["journalist_sig"]))

        journalist_fetching_sig = pki.verify_key(intermediate_verifying_key,
                                                 journalist_fetching_verifying_key,
                                                 None,
                                                 b64decode(content["journalist_fetching_sig"]))

    except Exception:
        return {"status": "KO"}, 400
    journalist_uid = sha3_256(journalist_verifying_key.to_string()).hexdigest()
    redis.sadd("journalists", json.dumps({"journalist_uid": journalist_uid,
                                          "journalist_key": b64encode(
                                            journalist_verifying_key.to_string()
                                          ).decode("ascii"),
                                          "journalist_sig": b64encode(
                                            journalist_sig
                                          ).decode("ascii"),
                                          "journalist_fetching_key": b64encode(
                                            journalist_fetching_verifying_key.to_string()
                                          ).decode("ascii"),
                                          "journalist_fetching_sig": b64encode(
                                            journalist_fetching_sig
                                          ).decode("ascii"),
                                          }))
    return {"status": "OK"}, 200


@app.route("/journalists", methods=["GET"])
def get_journalists():
    journalists_list = []
    journalists = redis.smembers("journalists")
    for journalist_json in journalists:
        journalists_list.append(json.loads(journalist_json.decode("ascii")))
    return {"status": "OK", "count": len(journalists), "journalists": journalists_list}, 200


@app.route("/file", methods=["POST"])
def download_file():
    try:
        assert ('file' in request.files)
        file = request.files['file']
        assert (len(file.filename) > 0)
    except Exception:
        return {"status": "KO"}, 400

    file_name = token_hex(32)
    file_id = token_hex(32)
    redis.set(f"file:{file_id}", file_name.encode("ascii"))

    file.save(f"{commons.UPLOADS}{file_name}.enc")

    return {"status": "OK", "file_id": file_id}, 200


@app.route("/file/<file_id>", methods=["GET"])
def get_file(file_id):
    file_name = redis.get(f"file:{file_id}")
    if not file_name:
        return {"status": "KO"}, 404
    else:
        file_name = file_name.decode('ascii')
        return send_file(f"{commons.UPLOADS}{file_name}.enc")


@app.route("/file/<file_id>", methods=["DELETE"])
def delete_file(file_id):
    file = redis.get(f"file:{file_id}")
    if not file:
        return {"status": "KO"}, 404
    else:
        file = file.decode('ascii')

        redis.delete(f"file:{file_id}")
        remove(f"{commons.UPLOADS}{file}.enc")
    return {"status": "OK"}, 200


@app.route("/ephemeral_keys", methods=["POST"])
def add_ephemeral_keys():
    content = request.json
    try:
        assert ("journalist_uid" in content)
        assert ("ephemeral_keys" in content)
    except Exception:
        return {"status": "KO"}, 400

    journalist_uid = content["journalist_uid"]
    journalists = redis.smembers("journalists")

    for journalist in journalists:
        journalist_dict = json.loads(journalist.decode("ascii"))
        if journalist_dict["journalist_uid"] == journalist_uid:
            journalist_verifying_key = pki.public_b642key(journalist_dict["journalist_key"])
    ephemeral_keys = content["ephemeral_keys"]

    for ephemeral_key_dict in ephemeral_keys:
        ephemeral_key = b64decode(ephemeral_key_dict["ephemeral_key"])
        ephemeral_key_verifying_key = VerifyingKey.from_string(ephemeral_key, curve=commons.CURVE)
        ephemeral_sig = b64decode(ephemeral_key_dict["ephemeral_sig"])
        ephemeral_sig = pki.verify_key(
            journalist_verifying_key,
            ephemeral_key_verifying_key,
            None,
            ephemeral_sig)
        redis.sadd(f"journalist:{journalist_uid}",
                   json.dumps({"ephemeral_key": b64encode(
                                 ephemeral_key_verifying_key.to_string()
                               ).decode("ascii"),
                               "ephemeral_sig": b64encode(
                                 ephemeral_sig
                               ).decode("ascii")}))

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


@app.route("/fetch", methods=["GET"])
def get_fetch():
    # SERVER EPHEMERAL CHALLENGE KEY
    request_ephemeral_key = SigningKey.generate(curve=commons.CURVE)
    potential_messages = []

    # retrieve all the message keys
    message_keys = redis.keys("message:*")
    for message_key in message_keys:
        message_id = message_key.decode('ascii').split(":")[1]
        # retrieve the message and load the json
        message_dict = json.loads(redis.get(message_key).decode('ascii'))

        message_server_gdh = VerifyingKey.from_public_point(
                                        pki.get_shared_secret(
                                            VerifyingKey.from_string(b64decode(message_dict["message_public_key"]), curve=commons.CURVE),
                                            request_ephemeral_key),
                                        curve=commons.CURVE).to_string()

        # calculate the sared key for message_id encryption
        ecdh = ECDH(curve=commons.CURVE)
        ecdh.load_private_key(request_ephemeral_key)
        ecdh.load_received_public_key_bytes(b64decode(message_dict["message_gdh"]))
        message_server_shared_secret = ecdh.generate_sharedsecret_bytes()
        box = nacl.secret.SecretBox(message_server_shared_secret[0:32])
        encrypted_message_id = box.encrypt(message_id.encode('ascii'))

        potential_messages.append({"gdh": b64encode(message_server_gdh).decode('ascii'),
                                   "enc": b64encode(encrypted_message_id).decode('ascii')})

    # add DECOY potential messages
    # TODO: add shuffling of the response dict
    for decoy in range(commons.MAX_MESSAGES - len(potential_messages)):
        potential_messages.append({
                                   "gdh": b64encode(SigningKey.generate(curve=commons.CURVE).verifying_key.to_string()).decode('ascii'),
                                   # message_id are 32 bytes and encryption overhead is 64 bytes
                                   "enc": b64encode(token_bytes(32+72)).decode('ascii')
            }
        )

    # TODO: add stronger timing attack mitigations (such as a random delay)
    sleep(uniform(0, 3.0))

    assert (len(potential_messages) == commons.MAX_MESSAGES)

    # padding to hide the number of meesages to be added later
    response_dict = {"status": "OK",
                     "count": len(potential_messages),
                     "messages": potential_messages}
    return response_dict, 200


@app.route("/message", methods=["POST"])
def send():
    content = request.json
    try:
        assert ("message_ciphertext" in content)
        assert ("message_public_key" in content)
        assert ("message_gdh" in content)
    except Exception:
        return {"status": "KO"}, 400
    message_dict = {
        # encrypted message
        "message_ciphertext": request.json["message_ciphertext"],
        # gj, public key part of the keypar generated by the sending journalist for every message
        "message_public_key": request.json["message_public_key"],
        # gkj, public part computer using the source public key and the per message secret key
        "message_gdh": request.json["message_gdh"]
    }
    # save the journalist to source reply in redis
    redis.set(f"message:{token_hex(32)}", json.dumps(message_dict))
    return {"status": "OK"}, 200


@app.route("/message/<message_id>", methods=["GET"])
def get_message(message_id):
    assert (len(message_id) == 64)
    message = redis.get(f"message:{message_id}")
    if message is not None:
        message_dict = json.loads(message.decode('ascii'))
        del message_dict["message_gdh"]
        response = {"status": "OK", "message": message_dict}
        return response, 200
    else:
        return {"status": "KO"}, 404


@app.route("/message/<message_id>", methods=["DELETE"])
def delete_message(message_id):
    assert (len(message_id) == 64)
    res = redis.delete(f"message:{message_id}")
    if res > 0:
        return {"status": "OK"}, 200
    else:
        return {"status": "KO"}, 404
