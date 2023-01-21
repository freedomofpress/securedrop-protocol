from base64 import b64decode
from hashlib import sha3_256
from os import mkdir, rmdir

import nacl.utils
from ecdsa import (InvalidCurveError, InvalidSharedSecretError, SigningKey,
                   VerifyingKey)
from ecdsa.ellipticcurve import INFINITY
from ecdsa.util import sigdecode_der, sigencode_der

import commons


# Used to deterministally generate keys based on the passphrase, only on the source side
# the class is kind of a hack: python-ecdsa wants a os.urandom() kind of interface
# but nacl.utils does not have an internal state even if seeded.
# Thus we use a seed to generate enough randoness for all the needed calls. Shall the
# pre-generated randomness end, an exception is forcefully raised.
class PRNG:
    def __init__(self, seed):
        assert (len(seed) == 32)
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


# We need to cryptographically veify this as these are the two functions
# used to process the challenge response. Refer to the documentation for
# a decription of the actual mechanism.
# Even if everything is ok, we must make sure that the server cannot leak stuff
# by serving crafted challenges instead of random ones
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


def public_b642key(b64_verifying_key):
    return VerifyingKey.from_string(b64decode(b64_verifying_key), curve=commons.CURVE)


# Loads a saved python ecdsa key from disk, if signing=False, load just the public-key
def load_key(name, signing=True):

    with open(f"{commons.DIR}/{name}.pem", "rb") as f:
        verifying_key = VerifyingKey.from_pem(f.read())

    if signing:
        with open(f"{commons.DIR}/{name}.key", "rb") as f:
            key = SigningKey.from_pem(f.read())
        assert (key.verifying_key == verifying_key)
        return key
    else:
        return verifying_key


# Generate a python-ecdsa keypair and save it to disk
def generate_key(name):
    key = SigningKey.generate(curve=commons.CURVE)

    with open(f"{commons.DIR}/{name}.key", "wb") as f:
        f.write(key.to_pem(format="pkcs8"))

    with open(f"{commons.DIR}/{name}.pem", "wb") as f:
        f.write(key.verifying_key.to_pem())

    return key


# Sign a given public key with the pubblid private key
def sign_key(signing_pivate_key, signed_public_key, signature_name):
    sig = signing_pivate_key.sign_deterministic(
        signed_public_key.to_string(),
        hashfunc=sha3_256,
        sigencode=sigencode_der
    )

    with open(signature_name, "wb") as f:
        f.write(sig)

    return sig


# Verify a signature
def verify_key(signing_public_key, signed_public_key, signature_name, sig=None):
    if not sig:
        with open(signature_name, "rb") as f:
            sig = f.read()
    signing_public_key.verify(sig, signed_public_key.to_string(), sha3_256, sigdecode=sigdecode_der)
    return sig


def generate_pki():
    try:
        rmdir(commons.DIR)
    except Exception:
        pass
    mkdir(commons.DIR)
    root_key = generate_key("root")
    intermediate_key = generate_key("intermediate")
    sign_key(root_key, intermediate_key.verifying_key, f"{commons.DIR}intermediate.sig")
    journalist_chal_keys, journalist_keys = generate_journalists(intermediate_key)
    return root_key, intermediate_key, journalist_chal_keys, journalist_keys


def verify_root_intermediate():
    root_verifying_key = load_key("root", signing=False)
    intermediate_verifying_key = load_key("intermediate", signing=False)
    verify_key(root_verifying_key, intermediate_verifying_key, f"{commons.DIR}intermediate.sig")
    return intermediate_verifying_key


def load_pki():
    root_key = load_key("root")
    intermediate_key = load_key("intermediate")
    verify_key(root_key.verifying_key, intermediate_key.verifying_key, f"{commons.DIR}intermediate.sig")
    journalist_keys = []
    for j in range(commons.JOURNALISTS):
        journalist_key = load_key(f"{commons.DIR}journalists/journalist_{j}")
        journalist_keys.append(journalist_key)
        verify_key(intermediate_key.verifying_key,
                   journalist_key.verifying_key,
                   f"{commons.DIR}journalists/journalist_{j}.sig")
    return root_key, intermediate_key, journalist_keys


def load_and_verify_journalist_keypair(journalist_id):
    intermediate_verifying_key = verify_root_intermediate()
    journalist_key = load_key(f"journalists/journalist_{journalist_id}")
    journalist_sig = verify_key(intermediate_verifying_key,
                                journalist_key.verifying_key,
                                f"{commons.DIR}journalists/journalist_{journalist_id}.sig")
    journalist_chal_key = load_key(f"journalists/journalist_chal_{journalist_id}")
    journalist_chal_sig = verify_key(intermediate_verifying_key,
                                     journalist_chal_key.verifying_key,
                                     f"{commons.DIR}journalists/journalist_chal_{journalist_id}.sig")

    return journalist_sig, journalist_key, journalist_chal_sig, journalist_chal_key


def load_and_verify_journalist_verifying_keys():
    intermediate_verifying_key = verify_root_intermediate()
    journalist_verying_keys = []
    for j in range(commons.JOURNALISTS):
        journalist_verifying_key = load_key(f"journalists/journalist_{j}", signing=False)
        verify_key(intermediate_verifying_key,
                   journalist_verifying_key,
                   f"{commons.DIR}journalists/journalist_{j}.sig")
        journalist_verying_keys.append(journalist_verifying_key)
    return journalist_verying_keys


def generate_journalists(intermediate_key):
    journalist_keys = []
    journalist_chal_keys = []
    mkdir(f"{commons.DIR}/journalists/")
    for j in range(commons.JOURNALISTS):
        journalist_key = generate_key(f"journalists/journalist_{j}")
        journalist_keys.append(journalist_key)
        sign_key(intermediate_key, journalist_key.verifying_key, f"{commons.DIR}journalists/journalist_{j}.sig")
        journalist_chal_key = generate_key(f"journalists/journalist_chal_{j}")
        journalist_chal_keys.append(journalist_chal_key)
        sign_key(intermediate_key, journalist_chal_key.verifying_key, f"{commons.DIR}journalists/journalist_chal_{j}.sig")

    return journalist_chal_keys, journalist_keys


def generate_ephemeral(journalist_key, journalist_id, journalist_uid):
    try:
        mkdir(f"{commons.DIR}/journalists/{journalist_uid}")
    except Exception:
        pass
    key = SigningKey.generate(curve=commons.CURVE)
    name = sha3_256(key.verifying_key.to_string()).hexdigest()

    with open(f"{commons.DIR}/journalists/{journalist_uid}/{name}.key", "wb") as f:
        f.write(key.to_pem(format="pkcs8"))

    with open(f"{commons.DIR}/journalists/{journalist_uid}/{name}.pem", "wb") as f:
        f.write(key.verifying_key.to_pem())

    sig = sign_key(journalist_key, key.verifying_key, f"{commons.DIR}/journalists/{journalist_uid}/{name}.sig")

    return sig, key


if __name__ == '__main__':
    generate_pki()
    # root_key, intermediate_key, journalist_keys = load_pki()
