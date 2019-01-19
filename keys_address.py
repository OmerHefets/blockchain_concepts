import secrets
import ecdsa

ECDSA_CURVE_ORDER = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'


def generate_private_key():
    bits_private_key = secrets.randbits(256)
    hex_private_key = hex(bits_private_key)[2:]
    # if the private key is bigger than the curve order, try again
    if int(hex_private_key, 16) > int(ECDSA_CURVE_ORDER, 16):
        hex_private_key = generate_private_key()
    return hex_private_key


# print(ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).get_verifying_key().to_string())