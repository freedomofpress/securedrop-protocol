#!/usr/bin/env python3
import pickle
from nacl.bindings import crypto_scalarmult
from nacl.hash import sha512
from nacl.encoding import RawEncoder
from nacl.public import SealedBox, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.hashlib import scrypt
from kyber import Kyber1024
from typing import Optional, Tuple, Union

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
        self.SK_DH = PrivateKey.generate()
        self.PK_DH = self.SK_DH.public_key

    def encrypt(
        self,
        msg: bytes,
        recipient: Union["Source", "Journalist"],
        PK_DH: bytes,
        PK_PKE: bytes,
    ) -> "Envelope":
        ME_SK_DH = PrivateKey.generate()
        ME_PK_DH = ME_SK_DH.public_key

        dh = DH(self.SK_DH.encode(), PK_DH.encode())
        dh_ME = DH(ME_SK_DH.encode(), PK_DH.encode())
        k = KDF(dh + dh_ME)
        ckey = PKE_Enc(PK_PKE, self.PK_DH.encode())

        if isinstance(self, Source) and isinstance(recipient, Journalist):
            pt = Plaintext(msg, self.PK_DH, self.PK_PKE, recipient)
        elif isinstance(recipient, Journalist):
            pt = Plaintext(msg, journalist=recipient)
        else:
            pt = Plaintext(msg)
        c = SE_Enc(k, pickle.dumps(pt))  # can't json.dumps() PyNaCl objects

        return Envelope(ckey, c, ME_PK_DH)


class Source(User):
    def __init__(self):
        super().__init__()
        self.SK_PKE = PrivateKey.generate()
        self.PK_PKE = self.SK_PKE.public_key

    def decrypt(self, ckey: bytes, c: bytes, ME_PK_DH: bytes) -> dict:
        J_PK_DH = PKE_Dec(self.SK_PKE, ckey)
        dh_S = DH(self.SK_DH.encode(), J_PK_DH)
        dh_ME = DH(self.SK_DH.encode(), ME_PK_DH.encode())
        k = KDF(dh_S + dh_ME)
        pt = pickle.loads(SE_Dec(k, c))

        return pt


class Newsroom:
    def __init__(self):
        self.NR_SK = PrivateKey.generate()
        self.NR_PK = self.NR_SK.public_key


class Journalist(User):
    def __init__(self, newsroom: Newsroom):
        super().__init__()

        self.newsroom = newsroom

        self.J_SK_SIG = PrivateKey.generate()
        self.J_PK_SIG = self.J_SK_SIG.public_key

        # TODO: sign PK_DH || J_PK_SIG by NR

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
        self,
        msg: bytes,
        PK_DH: Optional[bytes] = None,
        PK_PKE: Optional[bytes] = None,
        journalist: Optional[Journalist] = None,
    ):
        self.msg = msg
        self.PK_DH = PK_DH
        self.PK_PKE = PK_PKE
        if journalist is not None:
            self.journalist = (
                journalist.J_PK_SIG
            )  # Does it matter which public key we use here?
            self.newsroom = journalist.newsroom.NR_PK

    def __str__(self):
        try:
            return f"<Plaintext msg={self.msg} PK_DH={self.PK_DH} PK_PKE={self.PK_PKE} recipient={self.journalist} newsroom={self.newsroom}>"
        except AttributeError:
            return f"<Plaintext msg={self.msg} PK_DH={self.PK_DH} PK_PKE={self.PK_PKE}>"


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
    source = Source()

    print("\n\nTest 1: Source to Journalist")
    message_in = b"uber secret"
    envelope = source.encrypt(
        message_in, journalist, journalist.JE_PK_DH, journalist.JE_PK_PKE
    )
    print(f"{source} --> {message_in} --> {envelope}")
    message_out = journalist.decrypt(envelope.ckey, envelope.c, envelope.ME_PK_DH)
    print(f"{journalist} <-- {message_out} <-- {envelope}")
    assert message_out.msg == message_in

    print("\n\nTest 2: Journalist to Source")
    message2_in = b"mega secret"
    envelope2 = journalist.encrypt(message2_in, source, source.PK_DH, source.PK_PKE)
    print(f"{journalist} --> {message2_in} --> {envelope2}")
    message2_out = source.decrypt(envelope2.ckey, envelope2.c, envelope2.ME_PK_DH)
    print(f"{source} <-- {message2_out} <-- {envelope2}")
    assert message2_out.msg == message2_in

    print("\n\nTest 3: Journalist to Journalist")
    journalist2 = Journalist(newsroom)
    message3_in = b"internal memo"
    envelope3 = journalist.encrypt(
        message3_in, journalist2, journalist2.JE_PK_DH, journalist2.JE_PK_PKE
    )
    print(f"{journalist} --> {message3_in} --> {envelope3}")
    message3_out = journalist2.decrypt(envelope3.ckey, envelope3.c, envelope3.ME_PK_DH)
    print(f"{journalist2} <-- {message3_out} <-- {envelope3}")
    assert message3_out.msg == message3_in

    print("\n\nTest 4: Source to Source")
    source2 = Source()
    message4_in = b"covert comm :()"
    envelope4 = source.encrypt(
        message4_in,
        source2,
        source2.PK_DH,
        source2.PK_PKE,
    )
    print(f"{source} --> {message4_in} --> {envelope4}")
    message4_out = source2.decrypt(envelope4.ckey, envelope4.c, envelope4.ME_PK_DH)
    print(f"{source2} <-- {message4_out} <-- {envelope4}")
    assert message4_out.msg == message4_in


main()
