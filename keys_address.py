import secrets
import ecdsa
import codecs
import base58
import sys
import hashlib


ECDSA_CURVE_ORDER = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'


def generate_private_key():
    bits_private_key = secrets.randbits(256)
    # cut the hex representation
    hex_private_key = hex(bits_private_key)[2:]
    # if the private key is bigger than the curve order, try again with recursive call
    if int(hex_private_key, 16) > int(ECDSA_CURVE_ORDER, 16):
        hex_private_key = generate_private_key()
    # check key length (64), add zeros if needed
    hex_private_key = fix_key_length(hex_private_key, 64)
    return hex_private_key


def generate_public_key(hex_private_key):
    bytes_private_key = codecs.decode(hex_private_key, 'hex')
    # generate the pubKey from privKey with ECDSA lib
    bytes_public_key = ecdsa.SigningKey.from_string(bytes_private_key, curve=ecdsa.SECP256k1).get_verifying_key().to_string()
    hex_public_key = codecs.encode(bytes_public_key, 'hex')
    # modify pub_key display
    hex_public_key = hex(int(hex_public_key, 16))[2:]
    # check key length (128), add zeros if needed
    hex_public_key = fix_key_length(hex_public_key, 128)
    return hex_public_key


def generate_address(hex_public_key):
    # encode the key for hashing
    hex_public_key = hex_public_key.encode('utf-8')
    # make the sha256 hash first
    hashed_sha256_pubkey = hashlib.sha256(hex_public_key).hexdigest().encode('utf-8')
    # make the ripemd160 hash second
    h = hashlib.new('ripemd160')
    h.update(hashed_sha256_pubkey)
    pub_key_hash = h.hexdigest()
    return base58check(pub_key_hash, '00')


def base58check(payload, version):
    # add version to the payload (string concat)
    version_payload = (version + payload).encode('utf-8')
    # double SHA-256
    full_checksum = hashlib.sha256(version_payload).hexdigest().encode('utf-8')
    full_checksum = hashlib.sha256(full_checksum).hexdigest()
    version_payload = version_payload.decode('utf-8')
    checksum = full_checksum[0:8]
    version_payload += checksum
    # encoding to bytes for base58 encoding
    bytes_version_payload = bytes.fromhex(version_payload)
    base58check_encoded = base58.b58encode(bytes_version_payload)
    return base58check_encoded.decode('utf-8')


# fix the problem of too short keys in length by adding zeros
def fix_key_length(key, requested_sized):
    len_gap = requested_sized - len(key)
    if len_gap == 0:
        return key
    elif len_gap > 0:
        appended_zeros_string = '0' * len_gap
        key = (appended_zeros_string + key)
        return key
    else:
        sys.exit("Unidentified Error")


def generate():
    privKey = generate_private_key()
    pubKey = generate_public_key(privKey)
    addr = generate_address(pubKey)
    print("The private key:\n{}".format(privKey))
    print("The public key:\n{}".format(pubKey))
    print("The address:\n{}".format(addr))
    return privKey, pubKey, addr


(private_key, public_key, address) = generate()
