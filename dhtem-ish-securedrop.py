#!/usr/bin/env python3
import pickle
from nacl.bindings import crypto_scalarmult
from nacl.hash import sha512
from nacl.encoding import RawEncoder
from nacl.public import SealedBox, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.hashlib import scrypt
from kyber import Kyber1024
from threading import Lock
from typing import Optional, Tuple

SECRET_SIZE = 32


# Helpers for consistency with the notation in <https://github.com/freedomofpress/securedrop-protocol/issues/55#issuecomment-2454681466>:
def DH(secret: bytes, public: Optional[bytes] = None) -> bytes:
    if public is not None:
        return crypto_scalarmult(secret, public)
    else:
        raise NotImplementedError("just use PrivateKey.public_key")


def KDF(x: bytes) -> bytes:
    return scrypt(x, n=2, dklen=SECRET_SIZE)


def SE_Enc(key: bytes, message: bytes) -> bytes:
    box = SecretBox(key)
    return box.encrypt(message)


def SE_Dec(key: bytes, ciphertext: bytes):
    box = SecretBox(key)
    return box.decrypt(ciphertext)


def PKE_Enc(public_key: PublicKey, message: bytes) -> bytes:
    box = SealedBox(public_key)
    return box.encrypt(message)


def PKE_Dec(secret_key: PrivateKey, ciphertext: bytes):
    box = SealedBox(secret_key)
    return box.decrypt(ciphertext)


class User:
    def __init__(self):
        # Only one ephemeral key can be in use at a time.
        self.ME = Lock()

    def encrypt(self, *args, **kwargs):
        self.ME_SK_DH = PrivateKey.generate()
        self.ME_PK_DH = self.ME_SK_DH.public_key


class Source(User):
    def __init__(self):
        super().__init__()

        self.S_SK_DH = PrivateKey.generate()
        self.S_SK_PKE = PrivateKey.generate()

        self.S_PK_DH = self.S_SK_DH.public_key
        self.S_PK_PKE = self.S_SK_PKE.public_key

    def encrypt(
        self, msg: bytes, journalist: "Journalist", JE_PK_DH: bytes, JE_PK_PKE: bytes
    ) -> "Envelope":
        self.ME.acquire()
        super().encrypt(msg, JE_PK_DH, JE_PK_PKE)

        dh_S = DH(self.S_SK_DH.encode(), JE_PK_DH.encode())
        dh_ME = DH(self.ME_SK_DH.encode(), JE_PK_DH.encode())
        k = KDF(dh_S + dh_ME)
        ckey = PKE_Enc(JE_PK_PKE, self.S_PK_DH.encode())

        pt = Plaintext(msg, self.S_PK_DH, self.S_PK_PKE, journalist)
        c = SE_Enc(k, pickle.dumps(pt))  # can't json.dumps() PyNaCl objects

        env = Envelope(ckey, c, self.ME_PK_DH)
        self.ME.release()

        return env


class Newsroom:
    def __init__(self):
        self.NR_SK = PrivateKey.generate()
        self.NR_PK = self.NR_SK.public_key


class Journalist(User):
    def __init__(self, newsroom: Newsroom):
        super().__init__()
        self.newsroom = newsroom

        self.J_SK_DH = PrivateKey.generate()
        self.J_SK_SIG = PrivateKey.generate()

        self.J_PK_DH = self.J_SK_DH.public_key
        self.J_PK_SIG = self.J_SK_SIG.public_key

        # TODO: sign J_PK_DH || J_PK_SIG by NR

        self.JE_SK_DH = PrivateKey.generate()
        self.JE_SK_PKE = PrivateKey.generate()

        self.JE_PK_DH = self.JE_SK_DH.public_key
        self.JE_PK_PKE = self.JE_SK_PKE.public_key

        # TODO: sign JE_PK_DH and JE_PK_PKE by NR

    def decrypt(self, ckey: bytes, c: bytes, ME_PK_DH: bytes) -> dict:
        S_PK_DH = PKE_Dec(self.JE_SK_PKE, ckey)
        dh_S = DH(self.JE_SK_DH.encode(), S_PK_DH)
        dh_ME = DH(self.JE_SK_DH.encode(), ME_PK_DH.encode())
        k = KDF(dh_S + dh_ME)
        pt = pickle.loads(SE_Dec(k, c))

        assert pt.journalist == self.J_PK_SIG
        assert pt.newsroom == self.newsroom.NR_PK

        return pt


class Plaintext:
    def __init__(
        self, msg: bytes, S_PK_DH: bytes, S_PK_PKE: bytes, journalist: Journalist
    ):
        self.msg = msg
        self.S_PK_DH = S_PK_DH
        self.S_PK_PKE = S_PK_PKE
        self.journalist = (
            journalist.J_PK_SIG
        )  # Does it matter which public key we use here?
        self.newsroom = journalist.newsroom.NR_PK

    def __str__(self):
        return f"<Plaintext msg={self.msg} S_PK_DH={self.S_PK_DH} S_PK_PKE={self.S_PK_PKE} journalist={self.journalist} newsroom={self.newsroom}>"


class Envelope:
    def __init__(self, ckey: bytes, c: bytes, ME_PK_DH: bytes):
        self.ckey = ckey
        self.c = c
        self.ME_PK_DH = ME_PK_DH

    def __str__(self):
        return f"<Envelope ckey={self.ckey} c={self.c} ME_PK_DH={self.ME_PK_DH}>"


def main():
    newsroom = Newsroom()
    journalist = Journalist(newsroom)

    print("\n\nTest 1: Source to Journalist")
    message_in = b"uber secret"
    source = Source()

    envelope = source.encrypt(
        message_in, journalist, journalist.JE_PK_DH, journalist.JE_PK_PKE
    )
    print(f"{source} --> {message_in} --> {envelope}")
    message_out = journalist.decrypt(envelope.ckey, envelope.c, envelope.ME_PK_DH)
    print(f"{journalist} <-- {message_out} <-- {envelope}")

    """
    --- Transmissions not yet adapted from PQXDH to DHTEM-ish: ---

    print("\n\nTest 2: Journalist to Source")
    message2 = b"mega secret"
    server_message2 = send(message2, journalist, source)
    assert receive(server_message2, journalist, source) == message2
    print("Success!")

    print("\n\nTest 3: Journalist to Journalist")
    journalist2 = Journalist()
    message3 = b"hyper secret"
    server_message3 = send(message3, journalist, journalist2)
    assert receive(server_message3, journalist, journalist2) == message3
    print("Success!")

    print("\n\nTest 4: Source to Source")
    source2 = Source()
    message4 = b"covert comm :()"
    server_message4 = send(message4, source, source2)
    assert receive(server_message4, source, source2) == message4
    print("Success!")
    """


main()
