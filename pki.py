from base64 import b64decode
from hashlib import sha3_256
from os import mkdir, rmdir

from nacl.encoding import HexEncoder, Base64Encoder
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import randombytes_deterministic


from ecdsa import (InvalidCurveError, InvalidSharedSecretError)
from ecdsa.ellipticcurve import INFINITY

import commons


# Used to deterministally generate keys based on the passphrase, only on the source side
# the class is kind of a hack: python-ecdsa wants a os.urandom() kind of interface
# but nacl.utils does not have an internal state even if seeded.
# Thus we use a seed to generate enough randoness for all the needed calls. Shall the
# pre-generated randomness end, an exception is forcefully raised.
'''class PRNG:
    def __init__(self, seed):
        assert (len(seed) == 32)
        self.total_size = 4096
        self.seed = seed
        self.status = 0
        self.data = randombytes_deterministic(self.total_size, self.seed)

    def deterministic_random(self, size):
        if self.status + size >= self.total_size:
            raise RuntimeError("Ran out of buffered random values")
        return_data = self.data[self.status:self.status+size]
        self.status += size
        return return_data


def get_shared_secret(remote_pubkey, local_privkey):
    if not (local_privkey.curve == remote_pubkey.curve):
        raise InvalidCurveError("Curves for public key and private key is not equal.")

    # shared secret = PUBKEYtheirs * PRIVATEKEYours
    result = (remote_pubkey.pubkey.point * local_privkey.privkey.secret_multiplier)
    if result == INFINITY:
        raise InvalidSharedSecretError("Invalid shared secret (INFINITY).")

    return result
'''

# Loads a saved python ed25519 key from disk, if signing=False, load just the public-key
def load_key(name, signing=True):

    with open(f"{commons.DIR}/{name}.public", "r") as f:
        verify_key = VerifyKey(f.read(), Base64Encoder)

    if signing:
        with open(f"{commons.DIR}/{name}.key", "r") as f:
            key = SigningKey(f.read(), Base64Encoder)
        assert (key.verify_key == verify_key)
        return key
    else:
        return verify_key


# Generate a ed25519 keypair and save it to disk
def generate_key(name):
    key = SigningKey.generate()

    with open(f"{commons.DIR}/{name}.key", "w") as f:
        f.write(key.encode(encoder=Base64Encoder).decode('ascii'))

    with open(f"{commons.DIR}/{name}.public", "w") as f:
        f.write(key.verify_key.encode(encoder=Base64Encoder).decode('ascii'))

    return key


# Sign a given public key with the pubblid private key
def sign_key(signing_pivate_key, signed_public_key, signature_name):
    sig = signing_pivate_key.sign(signed_public_key.encode(), encoder=Base64Encoder)

    with open(signature_name, "w") as f:
        f.write(sig.signature.decode('ascii'))

    # signing_pivate_key.verify_key.verify(sig, encoder=Base64Encoder)
    # sooo the message can be base64 but the signature has to be byes, so the encoder
    # is applied only to the message apparently
    # signing_pivate_key.verify_key.verify(sig.message, b64decode(sig.signature), encoder=Base64Encoder)

    return sig


# Verify a signature
def verify_key_func(signing_public_key, signed_public_key, signature_name, sig=None):
    if not sig:
        with open(signature_name, "r") as f:
            sig = f.read()

    signing_public_key.verify(signed_public_key.encode(), b64decode(sig))
    return sig


def generate_pki():
    try:
        rmdir(commons.DIR)
    except Exception:
        pass
    mkdir(commons.DIR)
    root_key = generate_key("root")
    intermediate_key = generate_key("intermediate")
    sign_key(root_key, intermediate_key.verify_key, f"{commons.DIR}intermediate.sig")
    journalist_fetching_keys, journalist_keys = generate_journalists(intermediate_key)
    return root_key, intermediate_key, journalist_fetching_keys, journalist_keys


def verify_root_intermediate():
    root_verifying_key = load_key("root", signing=False)
    intermediate_verifying_key = load_key("intermediate", signing=False)
    verify_key_func(root_verifying_key, intermediate_verifying_key, f"{commons.DIR}intermediate.sig")
    return intermediate_verifying_key


def load_pki():
    root_key = load_key("root")
    intermediate_key = load_key("intermediate")
    verify_key_func(root_key.verif_key, intermediate_key.verify_key, f"{commons.DIR}intermediate.sig")
    journalist_keys = []
    for j in range(commons.JOURNALISTS):
        journalist_key = load_key(f"{commons.DIR}journalists/journalist_{j}")
        journalist_keys.append(journalist_key)
        verify_key_func(intermediate_key.verify_key,
                   journalist_key.verify_key,
                   f"{commons.DIR}journalists/journalist_{j}.sig")
    return root_key, intermediate_key, journalist_keys


def load_and_verify_journalist_keypair(journalist_id):
    intermediate_verifying_key = verify_root_intermediate()
    journalist_key = load_key(f"journalists/journalist_{journalist_id}")
    journalist_uid = sha3_256(journalist_key.verify_key.encode()).hexdigest()
    journalist_sig = verify_key_func(intermediate_verifying_key,
                                journalist_key.verify_key,
                                f"{commons.DIR}journalists/journalist_{journalist_id}.sig")
    journalist_fetching_key = load_key(f"journalists/journalist_fetching_{journalist_id}")
    journalist_fetching_sig = verify_key_func(intermediate_verifying_key,
                                         journalist_fetching_key.verify_key,
                                         f"{commons.DIR}journalists/journalist_fetching_{journalist_id}.sig")

    return journalist_uid, journalist_sig, journalist_key, journalist_fetching_sig, journalist_fetching_key


def load_and_verify_journalist_verifying_keys():
    intermediate_verifying_key = verify_root_intermediate()
    journalist_verying_keys = []
    for j in range(commons.JOURNALISTS):
        journalist_verifying_key = load_key(f"journalists/journalist_{j}", signing=False)
        verify_key_func(intermediate_verifying_key,
                   journalist_verifying_key,
                   f"{commons.DIR}journalists/journalist_{j}.sig")
        journalist_verying_keys.append(journalist_verifying_key)
    return journalist_verying_keys


def generate_journalists(intermediate_key):
    journalist_keys = []
    journalist_fetching_keys = []
    mkdir(f"{commons.DIR}/journalists/")
    for j in range(commons.JOURNALISTS):
        journalist_key = generate_key(f"journalists/journalist_{j}")
        journalist_keys.append(journalist_key)
        sign_key(intermediate_key, journalist_key.verify_key, f"{commons.DIR}journalists/journalist_{j}.sig")
        journalist_fetching_key = generate_key(f"journalists/journalist_fetching_{j}")
        journalist_fetching_keys.append(journalist_fetching_key)
        sign_key(intermediate_key, journalist_fetching_key.verify_key, f"{commons.DIR}journalists/journalist_fetching_{j}.sig")

    return journalist_fetching_keys, journalist_keys


def generate_ephemeral(journalist_key, journalist_id, journalist_uid):
    try:
        mkdir(f"{commons.DIR}/journalists/{journalist_uid}")
    except Exception:
        pass
    key = SigningKey.generate()
    name = sha3_256(key.verify_key.encode()).hexdigest()

    with open(f"{commons.DIR}/journalists/{journalist_uid}/{name}.key", "w") as f:
        f.write(key.verify_key.encode(Base64Encoder).decode('ascii'))

    with open(f"{commons.DIR}/journalists/{journalist_uid}/{name}.public", "w") as f:
        f.write(key.verify_key.encode(Base64Encoder).decode('ascii'))

    sig = sign_key(journalist_key, key.verify_key, f"{commons.DIR}/journalists/{journalist_uid}/{name}.sig")

    return sig, key


if __name__ == '__main__':
    generate_pki()
    # root_key, intermediate_key, journalist_keys = load_pki()
