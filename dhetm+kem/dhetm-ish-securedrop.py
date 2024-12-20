#!/usr/bin/env python3
import pickle
from nacl.bindings import crypto_scalarmult
from nacl.public import SealedBox, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.hashlib import scrypt
from typing import Optional, Tuple, Union
from kyber_py.ml_kem  import ML_KEM_768 

"""
from https://github.com/freedomofpress/securedrop-protocol/issues/55#issuecomment-2454681466
From a high level perspective: the sender encrypts its public DH share 
g^a using an asymmetric encryption scheme under the receiver's public key 
pk(sk_B). This way, the sender's identity g^a is not revealed unless the
adversary has access to sk_B.
Because the receiver's identity also needs to be kept secret, the PKE scheme
needs to provide anonymous encryption (i.e., the ciphertext doesn't
reveal the used public key).
"""

# Helpers for consistency with the notation in <https://github.com/freedomofpress/securedrop-protocol/issues/55#issuecomment-2454681466>:
def DH(secret: bytes, public: Optional[bytes] = None) -> bytes:
    if public is not None:
        return crypto_scalarmult(secret, public)
    else:
        raise NotImplementedError("just use PrivateKey.public_key")


def KDF(x: bytes) -> bytes:
    # TODO: "set dkLen to be a more standard length to get one key and then use
    # something like HKDF.Expand on this key with different context strings to
    # get each of the keys you actually need"
    return scrypt(x, n=2, dklen=SecretBox.KEY_SIZE)


def SE_Enc(key: bytes, message: bytes) -> bytes:
    """
    Encrypt @param message to @param key. Instead of encrypting
    to a public key of an external recipient (see PKE_Enc), encrypt
    with a symmetric shared key.
    """
    box = SecretBox(key)
    return box.encrypt(message)


def SE_Dec(key: bytes, ciphertext: bytes):
    """
    Decrypt @param ciphertext using @param key.
    """
    box = SecretBox(key)
    return box.decrypt(ciphertext)


def PKE_Enc(public_key: PublicKey, message: bytes) -> bytes:
    """
    Encrypt @param message to @param public_key (ie recipient public key).
    """
    box = SealedBox(public_key)
    return box.encrypt(message)


def PKE_Dec(secret_key: PrivateKey, ciphertext: bytes):
    """
    Decrypt @param cipherptext using @param secret key.
    """
    box = SealedBox(secret_key)
    return box.decrypt(ciphertext)


class User:
    def __init__(self):
        # Long term DH keypair 
        self.SK_DH = PrivateKey.generate()
        self.PK_DH = self.SK_DH.public_key

    def encrypt(
        self,
        msg: bytes,
        recipient: Union["Source", "Journalist"],
        PK_DH: bytes,
        PK_PKE: bytes,
        EK_MLKEM: bytes,
    ) -> "Envelope":
        """
        Encrypt a message to one party.
        @param msg       plaintext bytes
        @param recipient intended recipient, instance of Source or Journalist
        @param PK_DH     public key (signing) of recipient
        @param PK_PKE    public key (encryption) of recipient
        @param EK_MLKEM  KEM encapsulation key of recipient 
        """
        
        # Ephemeral per-message encryption key.
        # This provides for secrecy in case of a long-term key
        # being revealed
        ME_SK_DH = PrivateKey.generate()
        ME_PK_DH = ME_SK_DH.public_key

        # Diffie-Hellman key agreement between user's signing secret key and
        # recipient's signing public key. Used as input for the key k.
        dh = DH(self.SK_DH.encode(), PK_DH.encode())

        # Diffie-Hellman key agreement between message ephemeral secret key and
        # recipient's signing public key. Used as input for the key k.
        dh_ME = DH(ME_SK_DH.encode(), PK_DH.encode())
        
        # Key encapsulation mechanism. Used as input for the key k.
        # Encapsulate based on recipient encapsulation key.
        shared_pqkey_bytes, kem_ct_bytes = ML_KEM_768.encaps(EK_MLKEM)
        # Journalist discards shared_pqkey_bytes, because they won't need to
        # decrypt this envelope (it's not meant for them).

        # This is the shared secret, not the kem_ciphertext
        ss = shared_pqkey_bytes
                  # Formally, we're adding a KEM combiner: https://datatracker.ietf.org/doc/html/draft-ounsworth-cfrg-kem-combiners-05#name-kem-combiner-construction

        # Now derive a key from the material above.
        # This is a shared key k that both parties can resolve. To decrypt, the
        # recipient derives the key by solving the DH key agreements and key decapsulation
        # with their corresponding private keys.
        #
        # Is it fine to use ML-KEM as input for further key derivation?
        # According to NIST as of Oct '24, yes, but see this note:
        # "NIST notes that ML-KEM outputs a shared secret key which can be interpreted
        # as a shared secret (in the terminology of SP 800-56C) that does not require further key derivation.
        # However, further key derivation is allowed. One situation where this may be desired is 
        # for the purpose of combining an ML-KEM shared secret key with another shared secret.
        # NIST also notes that security of ML-KEM against an active adversary may or may not apply
        # once an ML-KEM key is combined with another shared secret.  NIST intends to offer guidance
        # on various key combiners in the forthcoming NIST SP 800-227."
        # https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/6_D0mMSYJZY/m/5CQ0aiAhAQAJ
        k = KDF(dh + dh_ME + ss)

        # Using the recipient's public encryption key, encrypt own long-term DH pubkey.
        ckey = PKE_Enc(PK_PKE, self.PK_DH.encode())

        if isinstance(self, Source) and isinstance(recipient, Journalist):
            # Attach own public encryption key for replies, because
            # otherwise journalist does not have access to it.
            pt = Plaintext(msg, self.PK_PKE, self.MLKEM_ENCAPS, recipient)
        elif isinstance(recipient, Journalist):
            # Journalist to Journalist
            # TODO: Attach JE_MLKEM_ENCAPS if it's a per-message key
            pt = Plaintext(msg, journalist=recipient)
        else:
            # Journalist to Source
            # TODO: Attach JE_MLKEM_ENCAPS if it's a per-message key
            pt = Plaintext(msg)

        # Encrypt plaintext to key k derived above.
        c = SE_Enc(k, pickle.dumps(pt))  # can't json.dumps() PyNaCl objects

        # Envelope contains:
        # (sender DH key encrypted to recipient, ciphertext, message pubkey, KEM ciphertext)
        return Envelope(ckey, c, ME_PK_DH, kem_ct_bytes)

    def decrypt(self, ckey: bytes, c: bytes, ME_PK_DH: bytes, KEM_CT: bytes) -> dict:
        """
        Decrypt a payload corresponding to an Envelope.
        @param ckey: sender identity key encrypted to recipient
        @param c: ciphertext
        @param ME_PK_DH: ephemeral message pubkey bytes
        @param KEM_CT: KEM ciphertext bytes, used to decapsulate shared pq secret
        """
        # Encryption and DH secret key. (In the case of Journalist, these are ephemeral keys.)
        SK_PKE = self.decryption_key("SK_PKE")
        SK_DH = self.decryption_key("SK_DH")

        # Decrypt the sender long-term key using own encryption secret key
        PK_DH = PKE_Dec(SK_PKE, ckey)

        # Key agreement between sender identity pubkey and my long-term DH share
        # to derive `dh` from the encrypt method ("my" DH secret key/"their" pubkey)
        dh = DH(SK_DH.encode(), PK_DH)
        # Key agreement between my identity (signing) secret key and the message ephemeral
        # pubkey, which was attached unencrypted to this payload, derives `dh_ME` from the
        # `encrypt` method
        dh_ME = DH(SK_DH.encode(), ME_PK_DH.encode())

        # Key decapsulation. TODO: here MLKEM_DECAPS is long term not ephemeral.
        # Todo: any assertions we can make?
        ss = ML_KEM_768.decaps(self.decryption_key("MLKEM_DECAPS"), KEM_CT)
        # Formally, we're adding a KEM combiner: https://datatracker.ietf.org/doc/html/draft-ounsworth-cfrg-kem-combiners-05#name-kem-combiner-construction

        # Combiner, yields `k` as from `encrypt`
        k = KDF(dh + dh_ME + ss)
        pt = pickle.loads(SE_Dec(k, c))

        return pt

    def decryption_key(self, suffix: str, prefix: str = "") -> str:
        """Helper function to keep User.decrypt() general. See Journalist.decryption_key()."""
        return getattr(self, f"{prefix}{suffix}")


class Source(User):
    """
    The source derives a master secret MS_S from the passphrase.
    It generates two secrets S_SK.DH || S_SK.PKE = KDF(MS_S) from
    the master secret.
    The corresponding public keys are S_PK.DH = DH(g, S_SK.DH) and
    S_PK.PKE = GetPub(S_SK.PKE)
    """
    def __init__(self):
        super().__init__()
        # Encryption keypair
        self.SK_PKE = PrivateKey.generate()
        self.PK_PKE = self.SK_PKE.public_key

        # Source generates one-time KEM encapsulation and decapsulation keys.
        # As with the other key material that the source generates, for the
        # purposes of the simplified (toy) implementation, use keygen() function,
        # for ease of using native APIs. The actual specification requires
        # all the source's key material to be derived from the master secret,
        # a diceware phrase that will be input into a kdf, which will yield
        # the long-term DH share, the SK_PKE, and kem material.
        # 
        # From the documentation:
        # encapsulation key is encoded as bytes of length 384*k + 32
        # decapsulation key is encoded as bytes of length 768*k + 96
        self.MLKEM_ENCAPS, self.MLKEM_DECAPS = ML_KEM_768.keygen()

class Newsroom:
    def __init__(self):
        self.NR_SK = PrivateKey.generate()
        self.NR_PK = self.NR_SK.public_key


class Journalist(User):
    """
    Journalist user.
    Journalists have additional key material/identity confirmation
    as compared to sources:
    * Their public long-term and encryption keys are signed
      by their newsroom (TODO/NOT IMPLEMENTED)
    * They generate an additional master secret (TODO/NOT IMPLEMENTED), from which
      is derived ephemeral signing and encryption keypairs and KEM material
      which are signed by their long-term (signing) key (TODO).
      Below, a single JE_SK_DH, JE_SK_PKE and their associated pubkeys
      (and JE_MLKEM_ENCAPS, JE_MLKEM_DECAPS) are used, but multiple such
      bundles would be generated.

    From the original spec:
        The journalist derives a master secret.
        It generates two long-term secrets, J_SK.DH || J_SK.SIG = KDF(MS_J)
        from the master secret.
        The corresponding public keys are J_PK.DH = DH(g, J_SK.DH) and 
        JPK.SIG=GetPub(J_SK.SIG).
        The tuple JPK.DH || JPK.SIG is signed by the newsroom.
        It generates ephemeral master secrets MS_JE.
        For each of them it generates two secrets JE_SK.DH||JE_SK.PKE=KDF(MS_JE) and
        corresponding public keys JE_PK.DH=DH(g,JE_SK.DH) and JE_PK.PKE=GetPub(JE_SK.PKE).
        The tuple JEPK,DH∥JEPK,PKE is signed using J_SK.SIG.
        [...]
        For example, JE_SK.PKE is a journalist's ephemeral private key used in a
        public-key encryption scheme. 
    """
    def __init__(self, newsroom: Newsroom):
        super().__init__()

        self.newsroom = newsroom
        # Journalist signing key. From the spec, this is one of two secret keys
        # derived from the long term master secret via KDF. For toy implmentation purposes, 
        # make use of libsodium keygen apis (instead of the master secret + kdf) to generate.
        self.J_SK_SIG = PrivateKey.generate()
        self.J_PK_SIG = self.J_SK_SIG.public_key

        # TODO: sign PK_DH || J_PK_SIG by NR_SK

        # Todo: from the spec, these keys are derived from an epehemeral master
        # secret. For toy implementation purposes, make use of libsodium keygen APIs.
        self.JE_SK_DH = PrivateKey.generate()
        self.JE_SK_PKE = PrivateKey.generate()

        # Journalist generates KEM encapsulation and decapsulation keys.
        # As with the other key material that the source generates, for the
        # purposes of the simplified (toy) implementation, use keygen() function,
        # for ease of using native APIs. From the spec, these are derived from
        # a master secret. For toy implementation purposes, make use of MLKEM APIs.
        # 
        # From the documentation:
        # encapsulation key is encoded as bytes of length 384*k + 32
        # decapsulation key is encoded as bytes of length 768*k + 96
        self.JE_MLKEM_ENCAPS, self.JE_MLKEM_DECAPS = ML_KEM_768.keygen()

        self.JE_PK_DH = self.JE_SK_DH.public_key
        self.JE_PK_PKE = self.JE_SK_PKE.public_key

        # TODO: confirm that JE_MLKEM_ENCAPS would be included as suggested
        # TODO: sign JE_PK_DH || JE_PK_PKE || JE_MLKEM_ENCAPS by J_SK_SIG

    def decrypt(self, *args, **kwargs) -> dict:
        pt = super().decrypt(*args, **kwargs)

        assert pt.journalist == self.J_PK_SIG
        assert pt.newsroom == self.newsroom.NR_PK

        return pt

    def decryption_key(self, suffix):
        """Helper function: journalists decrypt using ephemeral keys."""
        return super().decryption_key(suffix, "JE_")


class Plaintext:
    """
    Plaintext structure
    @param msg: cleartext message bytes
    @param PK_PKE: sender encryption pubkey. Sent from source to journalist
    @param MLKEM_ENCAPS: sender PQ encapsulation pubkey. Sent from source to journalist
    @param journalist: if recipient is journalist, include their identity (signing) pubkey
    """
    def __init__(
        self,
        msg: bytes,
        PK_PKE: Optional[bytes] = None,
        MLKEM_ENCAPS: Optional[bytes] = None,
        journalist: Optional[Journalist] = None,
    ):
        self.msg = msg
        self.PK_PKE = PK_PKE
        self.MLKEM_ENCAPS = MLKEM_ENCAPS
        if journalist is not None:
            self.journalist = (
                journalist.J_PK_SIG
            )  # Does it matter which of the journalist's public keys we use here?
            self.newsroom = journalist.newsroom.NR_PK

    def __str__(self):
        try:
            return f"<Plaintext msg={self.msg} PK_PKE={self.PK_PKE} MLKEM_ECAPS={self.MLKEM_ENCAPS} recipient={self.journalist} newsroom={self.newsroom}>"
        except AttributeError:
            # Journalist writes back to source
            return f"<Plaintext msg={self.msg} PK_PKE={self.PK_PKE} MLKEM_ECAPS={self.MLKEM_ENCAPS}>"


class Envelope:
    """
    Object representing components of message payload.
    @param ckey sender identity (signing) public key, encrypted to the recipient. 
    @param c ciphertext
    @param ME_PK_DH  Message ephemeral pubkey
    @param PQ_CT KEM ciphertext encrypted to the recipient. Used by receiving party to
    decapsulate and recover shared encapsulation key.
    """
    def __init__(self, ckey: bytes, c: bytes, ME_PK_DH: bytes, KEM_CT: bytes):
        self.ckey = ckey
        self.c = c
        self.ME_PK_DH = ME_PK_DH
        self.KEM_CT = KEM_CT

    def __str__(self):
        return f"<Envelope ckey={self.ckey} c={self.c} ME_PK_DH={self.ME_PK_DH} PQ_CT={self.KEM_CT}>"


def main():
    newsroom = Newsroom()
    journalist = Journalist(newsroom)
    source = Source()

    print("\n\nTest 1: Source to Journalist")
    message_in = b"uber secret"
    envelope = source.encrypt(
        message_in, journalist, journalist.JE_PK_DH, journalist.JE_PK_PKE, journalist.JE_MLKEM_ENCAPS
    )
    print(f"{source} --> {message_in} --> {envelope}")
    message_out = journalist.decrypt(envelope.ckey, envelope.c, envelope.ME_PK_DH, envelope.KEM_CT)
    print(f"{journalist} <-- {message_out} <-- {envelope}")
    assert message_out.msg == message_in

    print("\n\nTest 2: Journalist to Source")
    message2_in = b"mega secret"

    # TODO: Eventual "keybundle" refactor for clarity
    envelope2 = journalist.encrypt(message2_in, source, source.PK_DH, source.PK_PKE, source.MLKEM_ENCAPS)
    print(f"{journalist} --> {message2_in} --> {envelope2}")
    message2_out = source.decrypt(envelope2.ckey, envelope2.c, envelope2.ME_PK_DH, envelope2.KEM_CT)
    print(f"{source} <-- {message2_out} <-- {envelope2}")
    assert message2_out.msg == message2_in

    print("\n\nTest 3: Journalist to Journalist")
    journalist2 = Journalist(newsroom)
    message3_in = b"internal memo"
    envelope3 = journalist.encrypt(
        message3_in, journalist2, journalist2.JE_PK_DH, journalist2.JE_PK_PKE, journalist2.JE_MLKEM_ENCAPS
    )
    print(f"{journalist} --> {message3_in} --> {envelope3}")
    message3_out = journalist2.decrypt(envelope3.ckey, envelope3.c, envelope3.ME_PK_DH, envelope3.KEM_CT)
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
        source2.MLKEM_ENCAPS
    )
    print(f"{source} --> {message4_in} --> {envelope4}")
    message4_out = source2.decrypt(envelope4.ckey, envelope4.c, envelope4.ME_PK_DH, envelope4.KEM_CT)
    print(f"{source2} <-- {message4_out} <-- {envelope4}")
    assert message4_out.msg == message4_in

    print("\nTest cases successfully completed.\n")

main()
