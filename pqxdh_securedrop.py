from nacl.bindings import crypto_scalarmult
from nacl.hash import sha512
from nacl.encoding import RawEncoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from secrets import token_bytes
from kyber import Kyber1024

# Basic helpers
def symmetric_encrypt(key: bytes, message: bytes) -> bytes:
    box = SecretBox(key)
    return box.encrypt(message)

# NaCl symmetric encryption
def symmetric_decrypt(key: bytes, ciphertext: bytes):
    box = SecretBox(key)
    return box.decrypt(ciphertext)

# NaCl asymmetric (secretbox, DH+AEAD) encryption
def asymmetric_encrypt(secret_key: PrivateKey, public_key: PublicKey, message: bytes) -> bytes:
    box = Box(secret_key, public_key)
    return box.encrypt(message)

def asymmetric_decrypt(secret_key: PrivateKey, public_key: PublicKey, ciphertext: bytes):
    box = Box(secret_key, public_key)
    return box.decrypt(ciphertext)

# Keys common to all users
class User:
    def __init__(self):
        self.identity_key = PrivateKey.generate()
        self.fetching_key = PrivateKey.generate()
        self.pq_pk, self.pq_sk = Kyber1024.keygen()

# A source has all the basic keys
class Source(User):
    pass

# A journalist has all the basic keys, and the ephemeral keys (or one times keys, in Signal terminology)
class Journalist(User):
    def __init__(self):
        super().__init__()
        self.ephemeral_key = PrivateKey.generate()

# A message is composed by:
# - A per message ephemeral public key
# - The clue
# - The KEM ciphertext
# - The message ciphertext
#
# Upon receipt of the message, the server generate a message_id that is kept secret by the server
class ServerMessage():
    def __init__(self, message_ephemeral_public_key: PublicKey, kem_ct: bytes, clue: bytes, ciphertext=bytes):
        self.message_ephemeral_public_key = message_ephemeral_public_key
        self.kem_ct = kem_ct
        self.clue = clue
        self.ciphertext = ciphertext
        self.message_id = token_bytes(32)

    def __str__(self):
        return f"""
        Message ephemeral public key: {self.message_ephemeral_public_key.encode().hex()}
        KEM CT: {self.kem_ct.hex()[0:128]}...
        Clue: {self.clue.hex()}
        Ciphertext: {self.ciphertext.hex()}
        message_id: {self.message_id.hex()}
    """

# When we generate a server challenge we generateL
# - A "remixed" version of the per-message ephemeral public key
# - Aa ciphertext that is the result of symmetrically encrypting the message_id
#  using as a shared key the 3 party diffie hellman output
def generate_server_challenge(server_message: ServerMessage) -> tuple[bytes, bytes]:
    request_ephemeral_key = PrivateKey.generate()
    remixed_message_ephemeral_public_key = crypto_scalarmult(request_ephemeral_key.encode(), server_message.message_ephemeral_public_key.encode())
    encrypted_message_id = asymmetric_encrypt(request_ephemeral_key, PublicKey(server_message.clue), server_message.message_id)
    return remixed_message_ephemeral_public_key, encrypted_message_id

# When we solve a server challenge, we generate the same 3 party diffie hellman shared key
# and decrypt the encrypted message_id
def solve_server_challenge(recipient: Source|Journalist, remixed_message_ephemeral_public_key: bytes, encrypted_message_id: bytes) -> bytes:
    message_id = asymmetric_decrypt(recipient.fetching_key, PublicKey(remixed_message_ephemeral_public_key), encrypted_message_id)
    return message_id

# When we generate a clue, we just compute a DH between the per-message ephemeral secret key and the recipient fetching key
def generate_clue(message_ephemeral_key: PrivateKey, receiver: Source|Journalist) -> bytes:
    # The clue is just a DH targeting the receiver fething public key
    clue = crypto_scalarmult(message_ephemeral_key.encode(), receiver.fetching_key.public_key.encode())
    return clue

# This is textbook pqxdh: when a journalist is receiving, we expect the 4 DH version, using ephemeral keys
# when a source is receiving, we expect to do the 3 DH version since source keys are static
# we assume the KEM CT is unlinkable, is it?
def pqxdh_send(message_ephemeral_key: PrivateKey, sender: Source|Journalist, receiver: Source|Journalist) -> tuple[bytes, bytes]:
    # We cannot do dh1 because the source key is not advertised, meaning we cannot authenticate the sending source
    # If we are sending journalist to source, or journalist to journalist, then we can
    # dh1 = crypto_scalarmult(sender.identity_key.encode(), receiver.fetching_key.public_key.encode())
    if type(sender) == Source:
        dh1 = b""
    else:
        dh1 = crypto_scalarmult(sender.identity_key.encode(), receiver.fetching_key.public_key.encode())
    dh2 = crypto_scalarmult(message_ephemeral_key.encode(), receiver.identity_key.public_key.encode())
    dh3 = crypto_scalarmult(message_ephemeral_key.encode(), receiver.fetching_key.public_key.encode())
    if type(receiver) == Journalist:
        dh4 = crypto_scalarmult(message_ephemeral_key.encode(), receiver.ephemeral_key.public_key.encode())
    else:
        dh4 = b""
    kem_ct, ss = Kyber1024.enc(receiver.pq_pk)
    key = sha512(b"\xff" * 32 + dh1 + dh2 + dh3 + ss + dh4, encoder=RawEncoder)[0:SecretBox.KEY_SIZE]
    print({f"Dir: {type(sender)} -> {type(receiver)}"})
    print(f"DH1: {dh1.hex()}")
    print(f"DH2: {dh2.hex()}")
    print(f"DH3: {dh3.hex()}")
    print(f"DH4: {dh4.hex()}")
    print(f" SS: {ss.hex()}")
    print(f"KEY: {key.hex()}")
    return kem_ct, key

def pqxdh_receive(message_ephemeral_public_key: PublicKey, sender: Source|Journalist, receiver: Source|Journalist, kem_ct: bytes) -> bytes:
    if type(sender) == Journalist:
        dh1 = crypto_scalarmult(receiver.fetching_key.encode(), sender.identity_key.public_key.encode())
    else:
        dh1 = b""
    dh2 = crypto_scalarmult(receiver.identity_key.encode(), message_ephemeral_public_key.encode())
    dh3 = crypto_scalarmult(receiver.fetching_key.encode(), message_ephemeral_public_key.encode())
    if type(receiver) == Journalist:
        dh4 = crypto_scalarmult(receiver.ephemeral_key.encode(), message_ephemeral_public_key.encode())
    else:
        dh4 = b""
    ss = Kyber1024.dec(kem_ct, receiver.pq_sk)
    key = sha512(b"\xff" * 32 + dh1 + dh2 + dh3 + ss + dh4, encoder=RawEncoder)[0:SecretBox.KEY_SIZE]
    print(f"DH1: {dh1.hex()}")
    print(f"DH2: {dh2.hex()}")
    print(f"DH3: {dh3.hex()}")
    print(f"DH4: {dh4.hex()}")
    print(f" SS: {ss.hex()}")
    print(f"KEY: {key.hex()}")
    return key

# Compute all the parts and send!
def send(message: bytes, sender: Source|Journalist, receiver: Source|Journalist) -> ServerMessage:
    message_ephemeral_key = PrivateKey.generate()
    clue = generate_clue(message_ephemeral_key, receiver)
    kem_ct, key = pqxdh_send(message_ephemeral_key, sender, receiver)
    ciphertext = symmetric_encrypt(key, message)
    return ServerMessage(message_ephemeral_key.public_key, kem_ct, clue, ciphertext)

def receive(server_message: ServerMessage, sender: Source|Journalist, recipient: Source|Journalist) -> str:
    remixed_message_ephemeral_public_key, encrypted_message_id = generate_server_challenge(server_message)
    # Simulating a client challenge-solving
    message_id = solve_server_challenge(recipient, remixed_message_ephemeral_public_key, encrypted_message_id)
    # Verifying 3-party DH and message fetching
    assert(message_id == server_message.message_id)
    # Recomputing the pqxdh shared key
    key = pqxdh_receive(server_message.message_ephemeral_public_key, sender, recipient, server_message.kem_ct)
    return symmetric_decrypt(key, server_message.ciphertext)

def main():

    print("\n\nTest 1: Source to Journalist")
    message = b"uber secret"
    source = Source()
    journalist = Journalist()
    # Sending a message, first source to journalist
    server_message = send(message, source, journalist)
    # Simulating a fetching request, this would be a server procedure
    assert(receive(server_message, source, journalist) == message)
    print("Success!")

    print("\n\nTest 2: Journalist to Source")
    message2 = b"mega secret"
    server_message2 = send(message2, journalist, source)
    assert(receive(server_message2, journalist, source) == message2)
    print("Success!")

    print("\n\nTest 3: Journalist to Journalist")
    journalist2 = Journalist()
    message3 = b"hyper secret"
    server_message3 = send(message3, journalist, journalist2)
    assert(receive(server_message3, journalist, journalist2) == message3)
    print("Success!")    

    print("\n\nTest 4: Source to Source")
    source2 = Source()
    message4 = b"covert comm :()"
    server_message4 = send(message4, source, source2)
    assert(receive(server_message4, source, source2) == message4)
    print("Success!")

main()