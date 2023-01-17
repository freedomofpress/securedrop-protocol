#! /usr/bin/env python
#
# Provide an implementation of Linkable Spontaneus Anonymous Group Signature
# over elliptic curve cryptography.
#
# Implementation of cryptographic scheme from: https://eprint.iacr.org/2004/027.pdf
#
#
# Written in 2017 by Fernanddo Lobato Meeser and placed in the public domain.

import os
import hashlib
import functools
import ecdsa

from ecdsa.util import randrange
from ecdsa.ecdsa import curve_secp256k1
from ecdsa import SECP256k1
from ecdsa import numbertheory

def ring_signature(signing_key, key_idx, M, y, curve=SECP256k1, hash_func=hashlib.sha3_256):
    """
        Generates a ring signature for a message given a specific set of
        public keys and a signing key belonging to one of the public keys
        in the set.

        PARAMS
        ------

            signing_key: (int) The with which the message is to be anonymously signed.

            key_idx: (int) The index of the public key corresponding to the signature
                private key over the list of public keys that compromise the signature.

            M: (str) Message to be signed.

            y: (list) The list of public keys which over which the anonymous signature
                will be compose.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.

            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.

        RETURNS
        -------

            Signature (c_0, s, Y) :
                c_0: Initial value to reconstruct signature.
                s = vector of randomly generated values with encrypted secret to
                    reconstruct signature.
                Y = Link for current signer.

    """

    # Trasform public/private keys in the format expected by this function
    signing_key = int.from_bytes(signing_key.to_string(), 'big')
    y = list(map(lambda k: curve.generator.from_bytes(curve.curve, k.to_string()), y))


    n = len(y)
    c = [0] * n
    s = [0] * n

    # STEP 1
    H = H2(y, hash_func=hash_func)
    Y =  H * signing_key

    # STEP 2
    u = randrange(curve.order)
    c[(key_idx + 1) % n] = H1([y, Y, M, curve.generator * u, H * u], hash_func=hash_func)

    # STEP 3
    for i in [ i for i in range(key_idx + 1, n) ] + [i for i in range(key_idx)]:

        s[i] = randrange(curve.order)

        z_1 = (curve.generator * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        c[(i + 1) % n] = H1([y, Y, M, z_1, z_2], hash_func=hash_func)

    # STEP 4
    s[key_idx] = (u - signing_key * c[key_idx]) % curve.order
    return (c[0], s, Y)


def verify_ring_signature(message, y, c_0, s, Y, curve=SECP256k1, hash_func=hashlib.sha3_256):
    """
        Verifies if a valid signature was made by a key inside a set of keys.


        PARAMS
        ------
            message: (str) message whos' signature is being verified.

            y: (list) set of public keys with which the message was signed.

            Signature:
                c_0: (int) initial value to reconstruct the ring.

                s: (list) vector of secrets used to create ring.

                Y = (int) Link of unique signer.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.

            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.

        RETURNS
        -------
            Boolean value indicating if signature is valid.

    """
    y = list(map(lambda k: curve.generator.from_bytes(curve.curve, k.to_string()), y))

    n = len(y)
    c = [c_0] + [0] * (n - 1)

    H = H2(y, hash_func=hash_func)

    for i in range(n):
        z_1 = (curve.generator * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        if i < n - 1:
            c[i + 1] = H1([y, Y, message, z_1, z_2], hash_func=hash_func)
        else:
            return c_0 == H1([y, Y, message, z_1, z_2], hash_func=hash_func)

    return False


def map_to_curve(x, P=curve_secp256k1.p()):
    """
        Maps an integer to an elliptic curve.

        Using the try and increment algorithm, not quite
        as efficient as I would like, but c'est la vie.

        PARAMS
        ------
            x: (int) number to be mapped into E.

            P: (ecdsa.curves.curve_secp256k1.p) Modulo for elliptic curve.

        RETURNS
        -------
            (ecdsa.ellipticcurve.Point) Point in Curve
    """
    x -= 1
    y = 0
    found = False

    while not found:
        x += 1
        f_x = (x * x * x + 7) % P

        try:
            y = numbertheory.square_root_mod_prime(f_x, P)
            found = True
        except Exception as e:
            pass

    return ecdsa.ellipticcurve.Point(curve_secp256k1, x, y)


def H1(msg, hash_func=hashlib.sha3_256):
    """
        Return an integer representation of the hash of a message. The
        message can be a list of messages that are concatenated with the
        concat() function.

        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.

            hash_func: (function) a hash function which can recieve an input
                string and return a hexadecimal digest.

        RETURNS
        -------
            Integer representation of hexadecimal digest from hash function.
    """
    return int('0x'+ hash_func(concat(msg)).hexdigest(), 16)


def H2(msg, hash_func=hashlib.sha3_256):
    """
        Hashes a message into an elliptic curve point.

        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.

            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.
        RETURNS
        -------
            ecdsa.ellipticcurve.Point to curve.
    """
    return map_to_curve(H1(msg, hash_func=hash_func))


def concat(params):
    """
        Concatenates a list of parameters into a bytes. If one
        of the parameters is a list, calls itself recursively.

        PARAMS
        ------
            params: (list) list of elements, must be of type:
                - int
                - list
                - str
                - ecdsa.ellipticcurve.Point

        RETURNS
        -------
            concatenated bytes of all values.
    """
    n = len(params)
    bytes_value = [0] * n

    for i in range(n):

        if type(params[i]) is int:
            bytes_value[i] = params[i].to_bytes(32, 'big')
        if type(params[i]) is list:
            bytes_value[i] = concat(params[i])
        if type(params[i]) is ecdsa.ellipticcurve.Point:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')
        if type(params[i]) is str:
            bytes_value[i] = params[i].encode()

        if bytes_value[i] == 0:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')

    return functools.reduce(lambda x, y: x + y, bytes_value)


def stringify_point(p):
    """
        Represents an elliptic curve point as a string coordinate.

        PARAMS
        ------
            p: ecdsa.ellipticcurve.Point - Point to represent as string.

        RETURNS
        -------
            (str) Representation of a point (x, y)
    """
    return '{},{}'.format(p.x(), p.y())


def export_signature(y, message, signature, foler_name='./data', file_name='signature.txt'):
    """ Exports a signature to a specific folder and filename provided.

        The file contains the signature, the ring used to generate signature
        and the message being signed.
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')
    S = ''.join(map(lambda x: str(x) + ',', signature[1]))[:-1]
    Y = stringify_point(signature[2])

    dump = '{}\n'.format(signature[0])
    dump += '{}\n'.format(S)
    dump += '{}\n'.format(Y)

    arch.write(dump)

    pub_keys = ''.join(map(lambda yi: stringify_point(yi) + ';', y))[:-1]
    data = '{}\n'.format(''.join([ '{},'.format(m) for m in message])[:-1])
    data += '{}\n,'.format(pub_keys)[:-1]

    arch.write(data)
    arch.close()


def export_private_keys(s_keys, foler_name='./data', file_name='secrets.txt'):
    """ Exports a set  of private keys to a file.

        Each line in the file is one key.
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')

    for key in s_keys:
        arch.write('{}\n'.format(key))

    arch.close()


def main():
    curve  = ecdsa.SECP256k1
    number_participants = 10
    x = []
    y = []
    for i in range(number_participants):
        key = ecdsa.SigningKey.generate(curve=curve)
        x.append(key)
        y.append(key.verifying_key)

    message = "Every move we made was a kiss"

    i = 2
    signature = ring_signature(x[i], i, message, y, curve=curve)

    assert(verify_ring_signature(message, y, *signature, curve=curve))

if __name__ == '__main__':
    main()