import sys
import nacl.utils
from os import rmdir, mkdir
from ecdsa import SigningKey, VerifyingKey, NIST256p
from ecdsa.util import sigencode_der, sigdecode_der
from hashlib import sha3_256
from ecdsa.ellipticcurve import INFINITY
from commons import *

# used for deterministally generate keys based on the passphrase
class PRNG:
	def __init__(self, seed):
		assert(len(seed) == 32)
		self.total_size = 4096
		self.seed = seed
		self.status = 0
		self.data = nacl.utils.randombytes_deterministic(self.total_size, self.seed)

	def deterministic_random(self, size):
		if self.status + size >= self.total_size:
			raise RuntimeError("Ran out of buffered random values")
		return_data = self.data[self.status:self.status+size]
		self.status += size
		return return_data

def ec_mod_inverse(signing_key):
    # sanity checks??
    d = signing_key.privkey.secret_multiplier
    order = signing_key.privkey.order
    d_inv = pow(d, order-2, order)
    return d_inv

def get_shared_secret(remote_pubkey, local_privkey):
    if not (local_privkey.curve == remote_pubkey.curve):
        raise InvalidCurveError("Curves for public key and private key is not equal.")

    # shared secret = PUBKEYtheirs * PRIVATEKEYours
    result = (remote_pubkey.pubkey.point * local_privkey.privkey.secret_multiplier)
    if result == INFINITY:
        raise InvalidSharedSecretError("Invalid shared secret (INFINITY).")

    return result

def load_key(name):
	with open(f"{DIR}/{name}.key", "rb") as f:
		key = SigningKey.from_pem(f.read())

	with open(f"{DIR}/{name}.pem", "rb") as f:
		verifying_key = VerifyingKey.from_pem(f.read())

	assert(key.verifying_key == verifying_key)
	return key

def load_verifying_key(name):
	with open(f"{DIR}/{name}.pem", "rb") as f:
		verifying_key = VerifyingKey.from_pem(f.read())
	return verifying_key

def generate_key(name):
	key = SigningKey.generate(curve=CURVE)

	with open(f"{DIR}/{name}.key", "wb") as f:
		f.write(key.to_pem(format="pkcs8"))

	with open(f"{DIR}/{name}.pem", "wb") as f:
		f.write(key.verifying_key.to_pem())

	return key


def sign_key(signing_pivate_key, signed_public_key, signature_name):
	sig = signing_pivate_key.sign_deterministic(
		signed_public_key.to_string(),
		hashfunc=sha3_256,
		sigencode=sigencode_der
	)
	
	with open(signature_name, "wb") as f:
		f.write(sig)

	return sig

def verify_key(signing_public_key, signed_public_key, signature_name, sig=None):
	if not sig:
		with open(signature_name, "rb") as f:
			sig = f.read()
	signing_public_key.verify(sig, signed_public_key.to_string(), sha3_256, sigdecode=sigdecode_der)
	return sig

def generate_pki():
	try:
		rmdir(DIR)
	except:
		pass
	mkdir(DIR)
	root_key = generate_key("root")
	intermediate_key = generate_key("intermediate")
	sign_key(root_key, intermediate_key.verifying_key, f"{DIR}intermediate.sig")
	journalist_keys = generate_journalists(intermediate_key)
	return root_key, intermediate_key, journalist_keys

def verify_root_intermediate():
	root_verifying_key = load_verifying_key("root")
	intermediate_verifying_key = load_verifying_key("intermediate")
	verify_key(root_verifying_key, intermediate_verifying_key, f"{DIR}intermediate.sig")
	return intermediate_verifying_key

def load_pki():
	root_key = load_key("root")
	intermediate_key = load_key("intermediate")
	verify_key(root_key.verifying_key, intermediate_key.verifying_key, f"{DIR}intermediate.sig")
	journalist_keys = []
	for j in range(JOURNALISTS):
		journalist_key = load_key(f"{DIR}journalists/journalist_{j}")
		journalist_keys.append(journalist_key)
		verify_key(intermediate_key.verifying_key, journalist_key.verifying_key, f"{DIR}journalists/journalist_{j}.sig")
	return root_key, intermediate_key, journalist_keys

def load_public_pki():
	intermediate_verifying_key = verify_root_intermediate()
	journalist_keys = []
	for j in range(JOURNALISTS):
		journalist_key = load_key(f"{DIR}journalists/journalist_{j}")
		journalist_keys.append(journalist_key)
		verify_key(intermediate_key.verifying_key, journalist_key.verifying_key, f"{DIR}journalists/journalist_{j}.sig")
	return root_key, intermediate_key, journalist_keys

def load_and_verify_journalist_keypair(journalist_id):
	intermediate_verifying_key = verify_root_intermediate()
	journalist_key = load_key(f"journalists/journalist_{journalist_id}")
	sig = verify_key(intermediate_verifying_key, journalist_key.verifying_key, f"{DIR}journalists/journalist_{journalist_id}.sig")
	return sig, journalist_key

def load_and_verify_journalist_verifying_keys():
	intermediate_verifying_key = verify_root_intermediate()
	journalist_verying_keys = []
	for j in range(JOURNALISTS):
		journalist_verifying_key = load_verifying_key(f"journalists/journalist_{j}")
		verify_key(intermediate_verifying_key, journalist_verifying_key, f"{DIR}journalists/journalist_{j}.sig")
		journalist_verying_keys.append(journalist_verifying_key)
	return journalist_verying_keys

def generate_journalists(intermediate_key):
	journalist_keys = []
	mkdir(f"{DIR}/journalists/")
	for j in range(JOURNALISTS):
		journalist_key = generate_key(f"journalists/journalist_{j}")
		journalist_keys.append(journalist_key)
		sign_key(intermediate_key, journalist_key.verifying_key, f"{DIR}journalists/journalist_{j}.sig")
	return journalist_keys

def generate_ephemeral(journalist_key, journalist_id, journalist_uid):
	try:
		mkdir(f"{DIR}/journalists/{journalist_uid}")
	except:
		pass
	key = SigningKey.generate(curve=CURVE)
	name = sha3_256(key.verifying_key.to_string()).hexdigest()

	with open(f"{DIR}/journalists/{journalist_uid}/{name}.key", "wb") as f:
		f.write(key.to_pem(format="pkcs8"))

	with open(f"{DIR}/journalists/{journalist_uid}/{name}.pem", "wb") as f:
		f.write(key.verifying_key.to_pem())

	sig = sign_key(journalist_key, key.verifying_key, f"{DIR}/journalists/{journalist_uid}/{name}.sig")

	return sig, key

if __name__ == '__main__':
	generate_pki()
	#root_key, intermediate_key, journalist_keys = load_pki()
