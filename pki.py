from base64 import b64decode
from hashlib import sha3_256
from os import mkdir, rmdir

from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

import commons


# Loads a saved python ed25519 key from disk, if signing=False, load just the public-key
def load_key(name, keytype='sig', private=False):

    if keytype == 'sig':
        pub = VerifyKey
        priv = SigningKey
    elif keytype == 'enc':
        pub = PublicKey
        priv = PrivateKey
    else:
        return False

    if private:
        with open(f"{commons.DIR}/{name}.key", "r") as f:
            private_key = priv(f.read(), Base64Encoder)
        # assert (key.verify_key == verify_key)
        return private_key
    else:
        with open(f"{commons.DIR}/{name}.public", "r") as f:
            public_key = pub(f.read(), Base64Encoder)

        return public_key


# Generate a ed25519 keypair and save it to disk
def generate_key(name, keytype='sig'):
    if keytype == 'sig':
        generate_obj = SigningKey
    elif keytype == 'enc':
        generate_obj = PrivateKey
    else:
        return False

    key = generate_obj.generate()

    with open(f"{commons.DIR}/{name}.key", "w") as f:
        f.write(key.encode(encoder=Base64Encoder).decode('ascii'))

    with open(f"{commons.DIR}/{name}.public", "w") as f:
        if keytype == 'sig':
            f.write(key.verify_key.encode(encoder=Base64Encoder).decode('ascii'))
        else:
            f.write(key.public_key.encode(encoder=Base64Encoder).decode('ascii'))

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
    root_verifying_key = load_key("root", keytype='sig', private=False)
    intermediate_verifying_key = load_key("intermediate", keytype='sig', private=False)
    verify_key_func(root_verifying_key, intermediate_verifying_key, f"{commons.DIR}intermediate.sig")
    return intermediate_verifying_key


'''def load_pki():
    root_key = load_key("root")
    intermediate_key = load_key("intermediate")
    verify_key_func(root_key.verify_key, intermediate_key.verify_key, f"{commons.DIR}intermediate.sig")
    journalist_keys = []
    for j in range(commons.JOURNALISTS):
        journalist_key = load_key(f"{commons.DIR}journalists/journalist_{j}")
        journalist_keys.append(journalist_key)
        verify_key_func(intermediate_key.verify_key,
                   journalist_key.verify_key,
                   f"{commons.DIR}journalists/journalist_{j}.sig")
    return root_key, intermediate_key, journalist_keys
'''


def load_and_verify_journalist_keypair(journalist_id):
    intermediate_verifying_key = verify_root_intermediate()
    journalist_key = load_key(f"journalists/journalist_{journalist_id}", keytype='sig', private=True)
    journalist_uid = sha3_256(journalist_key.verify_key.encode()).hexdigest()
    journalist_sig = verify_key_func(intermediate_verifying_key,
                                     journalist_key.verify_key,
                                     f"{commons.DIR}journalists/journalist_{journalist_id}.sig")
    journalist_fetching_key = load_key(f"journalists/journalist_fetching_{journalist_id}", keytype='enc', private=True)
    journalist_fetching_sig = verify_key_func(intermediate_verifying_key,
                                              journalist_fetching_key.public_key,
                                              f"{commons.DIR}journalists/journalist_fetching_{journalist_id}.sig")

    return journalist_uid, journalist_sig, journalist_key, journalist_fetching_sig, journalist_fetching_key


def load_and_verify_journalist_verifying_keys():
    intermediate_verifying_key = verify_root_intermediate()
    journalist_verying_keys = []
    for j in range(commons.JOURNALISTS):
        journalist_verifying_key = load_key(f"journalists/journalist_{j}", private=False)
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
        journalist_key = generate_key(f"journalists/journalist_{j}", keytype='sig')
        journalist_keys.append(journalist_key)
        sign_key(intermediate_key, journalist_key.verify_key, f"{commons.DIR}journalists/journalist_{j}.sig")
        journalist_fetching_key = generate_key(f"journalists/journalist_fetching_{j}", keytype='enc')
        journalist_fetching_keys.append(journalist_fetching_key)
        sign_key(intermediate_key, journalist_fetching_key.public_key, f"{commons.DIR}journalists/journalist_fetching_{j}.sig")

    return journalist_fetching_keys, journalist_keys


def generate_ephemeral(journalist_key, journalist_id, journalist_uid):
    try:
        mkdir(f"{commons.DIR}/journalists/{journalist_uid}")
    except Exception:
        pass
    key = PrivateKey.generate()
    name = sha3_256(key.public_key.encode()).hexdigest()

    with open(f"{commons.DIR}/journalists/{journalist_uid}/{name}.key", "w") as f:
        f.write(key.encode(Base64Encoder).decode('ascii'))

    with open(f"{commons.DIR}/journalists/{journalist_uid}/{name}.public", "w") as f:
        f.write(key.public_key.encode(Base64Encoder).decode('ascii'))

    sig = sign_key(journalist_key, key.public_key, f"{commons.DIR}/journalists/{journalist_uid}/{name}.sig")

    return sig, key


if __name__ == '__main__':
    generate_pki()
    # root_key, intermediate_key, journalist_keys = load_pki()
