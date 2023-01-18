import sys
from os import rmdir, mkdir
from ecdsa import SigningKey, VerifyingKey, NIST256p
from ecdsa.util import sigencode_der, sigdecode_der
from hashlib import sha3_256

DIR = "keys/"
JOURNALISTS = 10
#CURVE = Ed25519
CURVE = NIST256p

def reset():
	rmdir(DIR)

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

def generate_ephemeral(journalist_key, journalist_id):
	try:
		mkdir(f"{DIR}/journalists/ephemeral_{journalist_id}")
	except:
		pass
	key = SigningKey.generate(curve=CURVE)
	name = sha3_256(key.verifying_key.to_string()).hexdigest()

	with open(f"{DIR}/journalists/ephemeral_{journalist_id}/{name}.key", "wb") as f:
		f.write(key.to_pem(format="pkcs8"))

	with open(f"{DIR}/journalists/ephemeral_{journalist_id}/{name}.pem", "wb") as f:
		f.write(key.verifying_key.to_pem())

	sig = sign_key(journalist_key, key.verifying_key, f"{DIR}/journalists/ephemeral_{journalist_id}/{name}.sig")

	return sig, key

def main():
	if len(sys.argv) > 1:
		if sys.argv[1] == 'generate':
			generate_pki()
	#root_key, intermediate_key, journalist_keys = load_pki()

main()