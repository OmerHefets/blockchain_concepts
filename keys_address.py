import secrets
import ecdsa
import codecs
import base58

ECDSA_CURVE_ORDER = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'


def generate_private_key():
    bits_private_key = secrets.randbits(256)
    hex_private_key = hex(bits_private_key)[2:]
    # if the private key is bigger than the curve order, try again
    if int(hex_private_key, 16) > int(ECDSA_CURVE_ORDER, 16):
        hex_private_key = generate_private_key()
    return hex_private_key


def generate_public_key(hex_private_key):
    bytes_private_key = codecs.decode(hex_private_key, 'hex')
    print(bytes_private_key)
    bytes_public_key = ecdsa.SigningKey.from_string(bytes_private_key, curve=ecdsa.SECP256k1).get_verifying_key().to_string()
    hex_public_key = codecs.encode(bytes_public_key, 'hex')
    # modify pub_key display
    hex_public_key = hex(int(hex_public_key, 16))[2:]
    return hex_public_key


#def generate_address(hex_public_key):


priv = generate_private_key()
print(priv)
print(generate_public_key(priv))
