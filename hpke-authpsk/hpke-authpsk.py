#!/usr/bin/env python3
import hybrid_pke
from nacl.bindings import crypto_scalarmult
from nacl.public import Box, PrivateKey
from typing import Optional, Tuple, Union
from kyber_py.ml_kem  import ML_KEM_768

# HPKE settings
HPKE_MESSAGE = hybrid_pke.default(mode=hybrid_pke.Mode.AUTH_PSK)
HPKE_METADATA = hybrid_pke.default() # TODO: PQ/T hybrid KEM
HPKE_INFO=b""
HPKE_AAD=b""
HPKE_PSK_ID = b"PSK_INFO_ID_TAG" # Spec requires a tag, todo

# Toy purposes, safe metadata parser + kem choices needed 
LEN_DHKEM_ENCAPS = 32
LEN_SENDER_DH_KEY = 32
LEN_PQKEM_ENCAPS = 1088

def GenerateDHAKEMKeypair() -> Tuple[bytes, bytes]:
    """
    HPKE (DH-AKEM, supports AuthEnc/AuthDec) keypair
    """
    # (sk, pk)
    return HPKE_MESSAGE.generate_key_pair()

def GenerateDHKeypair() -> Tuple[bytes, bytes]:
    """
    Generic DH keypair (fetch, long-term sign, mgdh)
    """
    sk = PrivateKey.generate()
    pk = sk.public_key
    return (sk.encode(), pk.encode())

def GeneratePQKEMKeypair():
    """
    Generate PQ KEM keypair
    """
    # TODO: Ideally HPKE_METADATA.generate_key_pair(kem=$hybridpqkem) (not yet supported by hpke lib)
    encaps, decaps = ML_KEM_768.keygen()
    return (encaps, decaps)

def DH(secret: bytes, public: Optional[bytes] = None) -> bytes:
    if public is not None:
        return crypto_scalarmult(secret, public)
    else:
        raise NotImplementedError("just use PrivateKey.public_key")

class User():

    def encrypt(self, plaintext: bytes, recipient: Union["Source", "Journalist"]) -> "Envelope":
        """
        Encrypt a plaintext message to a given recipient using HPKE's AuthPSK mode with
        a PQ shared secret as the PSK. The encrypted message is not signed directly by the
        sender, but incorporates an ephemeral message key, which maintains message-level
        deniability while preserving sender authentication.

        For message decryption, in addition to the ciphertext, the receiver needs the
        following information, encrypted via an (unauthenticated) HPKE.seal() per RFC9180
        section 9.9, Metadata Protection:

          * the sender's DH-AKEM pubkey
          * the (PQ/T KEM TBD, here MLKEM768) encpasulation of the PQ shared secret (PSK)
          * the (DH-AKEM, non-PQ) encapsulation of the DH-AKEM message shared secret

        Finally, a "Clue" (mgdh) is generated to allow the server to obliviously transfer
        messages for receiver.

        Return an Envelope, representing the entire payload to the sever, that contains:

          * the message ciphertext
          * the sealed metadata
          * the encapsulation of the metadata shared secret
          * the two parts of the mgdh/"clue" (ephemeral DH pubkey + mgdh)
        """
        # Step 1: PQ shared secret (PSK) and its encapsulation
        pq_ss, pq_ss_enc = ML_KEM_768.encaps(recipient.get_pqkem_encaps())

        # Step 2: HPKE AuthPSK encrypt the message.
        # TODO: structured serializable Message object that includes reply keys/signatures
        # TODO/discuss: source and journo construct different format messages per @lumaier
        dhkem_ss_encaps, message_ct = HPKE_MESSAGE.seal(recipient.get_dh_pk(), HPKE_INFO, HPKE_AAD, plaintext, psk=pq_ss, psk_id=HPKE_PSK_ID, sk_s=self._get_dh_sk())

        # Step 3: Seal metadata needed for decryption.
        # TODO: Use a PQ/T hyrid KEM to seal the metadata. Could this be the PQ KEM pubkey?
        sender_reply_key_bytes = self.get_dh_pk()
        metadata_bytes = dhkem_ss_encaps + pq_ss_enc + sender_reply_key_bytes
        metadata_encap, metadata_ct = HPKE_METADATA.seal(recipient.get_metadata_encaps(), HPKE_INFO, HPKE_AAD, metadata_bytes)

        # Step 4: Build message clue (mgdh)
        # This creates a *new* ephemeral DH key (X) only used for mgdh.
        # Per conversation with ETHZ, it is intentional that this is not linked to the message.
        recipient_pk_fetch = recipient.get_fetch_pk()
        sk_gdh, pk_gdh = GenerateDHKeypair()
        mgdh = DH(sk_gdh, recipient_pk_fetch)

        # Bundle everything together
        return Envelope(cmessage=message_ct, cmetadata=metadata_ct, metadata_encap=metadata_encap, mgdh_pubkey=pk_gdh, mgdh=mgdh)

    def decrypt(self, envelope: "Envelope") -> "Plaintext":
        # Decaps metadata
        metadata_untrusted = HPKE_METADATA.open(envelope.metadata_encap, self._get_metadata_decaps(), HPKE_INFO, HPKE_AAD, envelope.cmetadata)

        # (toy) parse metadata
        shared_dhkem_encap_untrusted = metadata_untrusted[0:LEN_DHKEM_ENCAPS]
        shared_pqkem_encap_untrusted = metadata_untrusted[LEN_DHKEM_ENCAPS:(LEN_DHKEM_ENCAPS+LEN_PQKEM_ENCAPS)]
        sender_pkey_bytes_untrusted = metadata_untrusted[-1*LEN_SENDER_DH_KEY:]

        # Decaps PQKEM to get shared secret, used as PSK
        shared_secret_pqkem_untrusted = ML_KEM_768.decaps(self._get_pqkem_decaps(), shared_pqkem_encap_untrusted)

        # Authenticate and decrypt message
        message_bytes_untrusted = HPKE_MESSAGE.open(shared_dhkem_encap_untrusted, self._get_dh_sk(), HPKE_INFO, HPKE_AAD, envelope.cmessage, psk=shared_secret_pqkem_untrusted, psk_id=HPKE_PSK_ID, pk_s=sender_pkey_bytes_untrusted)

        return Plaintext(message_bytes_untrusted, sender_pkey_bytes_untrusted)

    def _get_dh_sk(self):
        """
        DH-AKEM decaps/private key used for authenticated (non-PQ) encryption
        """
        raise NotImplementedError("child must implement!")

    def get_dh_pk(self):
        """
        DH-AKEM encaps/public key used for authenticated encryption
        """
        raise NotImplementedError("child must implement!")

    def _get_pqkem_decaps(self):
        """
        PQ-KEM key used to contribute to HPKE Auth Enc.
        Can be purely PQ since it is one input to a shared (hybrid/combined) secret.
        """
        raise NotImplementedError("child must implement!")

    def get_pqkem_encaps(self):
        """
        PQ-KEM key used to contribute to HPKE Auth Enc.
        Can be purely PQ since it is one input to a shared (hybrid/combined) secret.
        """
        raise NotImplementedError("child must implement!")

    # TODO/discuss: can we use the PQ KEM key?
    def _get_metadata_decaps(self):
        """
        PKE (Metadata seal). This should be a Hybrid (PQ/T) KEM.
        """
        raise NotImplementedError("child must implement!")

    def get_metadata_encaps(self):
        """
        PKE (Metadata seal). This should be a Hybrid (PQ/T) KEM.
        """
        raise NotImplementedError("child must implement!")
    
    def _get_fetch_sk(self):
        """
        DH secret key used for message-fetching (compute mgdh)
        """
        raise NotImplementedError("child must implement!")

    def get_fetch_pk(self):
        """
        DH public key used for message-fetching
        """
        raise NotImplementedError("child must implement!")

    # Not yet implemented
    def fetch(self, clues: list["Clue"]) -> list["Envelope"]:
        message_ids = []
        my_messages = []
        for clue in clues:
            try:
                # A = g^a mod p = (sharedbase**a) % sharedprime, a is alicesecret
                # B = g^b mod p, b is bobsecret (sharedbase**b) % sharedprime
                # compute: ss = (B ** alicesecret) % p  = (A ** bobsecret) % p
                # (pubkey ** privkey) % prime
                pmgdh = clue.cclue # (= DH(SE_SK, DH(ME_SK, JE_PK)))
                box = Box(self._get_fetch_sk(), pmgdh)
                message_id = box.decrypt(clue.cmessage_id)
                message_ids.append[message_id]
                my_messages.append[clue.envelope]
            except Exception:
                continue

        return my_messages

class Journalist(User):
    def __init__(self, newsroom: Newsroom):
        super().__init__()
        self.newsroom = newsroom

        # Longterm keys
        self._sk_dh_fetch, self._pk_dh_fetch = GenerateDHKeypair() # Long-term fetch
        self._j_sk_sig, self._j_pk_sig = GenerateDHKeypair() # Long-term sign
        # Not shown: newsroom signs long-term keys

        # Ephemeral keys
        self._je_sk_dh, self._je_pk_dh = GenerateDHAKEMKeypair()
        self._je_encaps_pqkem, self._je_decaps_pqkem = GeneratePQKEMKeypair()
        # TODO: PQ/T hybrid KEM kepair; can it be the same key as above?
        self._je_sk_metadata, self._je_pk_metadata = HPKE_METADATA.generate_key_pair()
        # Not shown: Sign ephemeral keys with long-term signing key

        # Eventually, advertise pubkey bundles. Keys should be context-bound/tagged
        # self.pubkey_bundles = [KeyBundle(...)]

    def get_metadata_encaps(self):
        # Should be PQ/T KEM decaps/encaps, used for unauth HPKE.seal()
        return self._je_pk_metadata

    def _get_metadata_decaps(self):
        # Should be PQ/T KEM decaps/encaps, used for unauth HPKE.seal()
        return self._je_sk_metadata

    def _get_pqkem_decaps(self):
        return self._je_decaps_pqkem

    def get_pqkem_encaps(self):
        return self._je_encaps_pqkem
        
    def get_dh_pk(self):
        return self._je_pk_dh

    def _get_dh_sk(self):
        return self._je_sk_dh

    def get_fetch_pk(self):
        return self._pk_dh_fetch

    def _get_fetch_sk(self):
        return self._sk_dh_fetch

    def _get_sk_sig(self):
        return self._j_sk_sig

    def get_pk_sig(self):
        return self._j_pk_sig

class Source(User):
    def __init__(self):
        super().__init__()
        self._sk_dh, self._pk_dh = GenerateDHAKEMKeypair()
        self._encaps_pqkem, self._decaps_pqkem = GeneratePQKEMKeypair()
        self._sk_fetch, self._pk_fetch = GenerateDHKeypair()

        # TODO: PQ/T hybrid KEM keypair. Can it be PQKEM key?
        self._sk_metadata, self._pk_metadata = HPKE_METADATA.generate_key_pair()

    def get_metadata_encaps(self):
        # Should be PQ/T KEM decaps/encaps, used for unauth HPKE.seal()
        return self._pk_metadata

    def _get_metadata_decaps(self):
        # Should be PQ/T KEM decaps/encaps, used for unauth HPKE.seal()
        return self._sk_metadata

    def _get_pqkem_decaps(self):
        return self._decaps_pqkem

    def get_pqkem_encaps(self):
        return self._encaps_pqkem
        
    def get_dh_pk(self):
        return self._pk_dh

    def _get_dh_sk(self):
        return self._sk_dh

    def get_fetch_pk(self):
        return self._pk_fetch

    def _get_fetch_sk(self):
        return self._sk_fetch

class Newsroom():
    def __init__(self, name: Optional[str] = None):
        self.name = name
        # Long-term signing key
        self._sk_dh, self._pk_dh = GenerateDHKeypair()

class Plaintext():
    def __init__(self, msg: bytes, sender_key: bytes, recipient_reply_key: Optional[bytes] = None):
        self.msg = msg
        self.sender_key = sender_key
        self.recipient_reply_key = recipient_reply_key
        # todo: newsroom

    def __str__(self):
        return f"<Plaintext msg={self.msg} sender_key={self.sender_key} recipient={self.recipient_reply_key}>"

class Envelope():
    """
    Entire message payload.

    @param cmessage auth-encrypted ciphertext (Message)
    @param cmetadata encrypted metadata (contains material needed to decrypt ciphertext)
    @param metadata_enc encapsulated metadata shared secret (needed to decrypt metadata)
    @param mgdh_pubkey X (ephemeral DH pubkey)
    @param mgdh Z (DH(x, jfetch)) aka "clue"

    """
    def __init__(self, cmessage: bytes, cmetadata: bytes, metadata_encap: bytes, mgdh_pubkey: bytes, mgdh: bytes):
        self.cmessage = cmessage
        # Encrypted metadata contains 3 things: DH-KEM ss encaps, PQ-KEM ss encaps, and sender key
        self.metadata_encap = metadata_encap
        self.cmetadata = cmetadata
        self.mgdh_x = mgdh_pubkey
        self.mgdh_z = mgdh

# Not implemented, but designed to show plaintext message structure (message, reply keys, etc.)
# Everything will be serialized then encrypted
class Message():
    """
    TODO message structure differs for source and journo in @lumaier thesis
    for sources:
    m <- msg || Sdh.pk || Spke.pk || Skem.pk || Sfetch.pk || Rsig.pk || NR

    for journalists:
    m <- msg || S || Jsig.pk || Jfetch.pk || Jdh.pk || newsrm sig || NR key
    """
    pass

# Not yet implemented
class Clue():
    """
    Example of associating mgdh (clue), message id, and envelope.
    For toy purposes, rather than separate (clue, message_id)
    and (message_id, envelope) objects, associate message payload with clue directly.
    """
    def __init__(self, cclue: bytes, cmessage_id: bytes, envelope: "Envelope"):
        self.cclue = cclue
        self.cmessage_id = cmessage_id
        self.envelope = envelope

def main():
    newsroom = Newsroom()
    journalist = Journalist(newsroom)
    source = Source()

    print("\n\nTest 1: Source to Journalist")
    message_in = b"uber secret"
    envelope = source.encrypt(plaintext=message_in, recipient=journalist)
    print(f"{source} --> {message_in} --> {envelope}")
    message_out = journalist.decrypt(envelope)
    print(f"{journalist} <-- {message_out} <-- {envelope}")
    assert message_out.msg == message_in

    print("\n\nTest 2: Journalist to Source")
    message2_in = b"mega secret"

    envelope2 = journalist.encrypt(message2_in, source)
    print(f"{journalist} --> {message2_in} --> {envelope2}")
    message2_out = source.decrypt(envelope2)
    print(f"{source} <-- {message2_out} <-- {envelope2}")
    assert message2_out.msg == message2_in

    print("\n\nTest 3: Journalist to Journalist")
    journalist2 = Journalist(newsroom)
    message3_in = b"internal memo"
    envelope3 = journalist.encrypt(
        message3_in, journalist2)
    print(f"{journalist} --> {message3_in} --> {envelope3}")
    message3_out = journalist2.decrypt(envelope3)
    print(f"{journalist2} <-- {message3_out} <-- {envelope3}")
    assert message3_out.msg == message3_in

    print("\n\nTest 4: Source to Source")
    source2 = Source()
    message4_in = b"covert comm :()"
    envelope4 = source.encrypt(
        message4_in,
        source2
    )
    print(f"{source} --> {message4_in} --> {envelope4}")
    message4_out = source2.decrypt(envelope4)
    print(f"{source2} <-- {message4_out} <-- {envelope4}")
    assert message4_out.msg == message4_in

    print("\nTest cases successfully completed.\n")

main()