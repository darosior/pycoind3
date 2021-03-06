# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


from . import base58

from .ecdsa.ecdsa import point_is_valid
from .ecdsa import SECP256k1 as curve
from .ecdsa.numbertheory import square_root_mod_prime
from .ecdsa.util import number_to_string, string_to_number

from .hash import hash160

__all__ = [
    'compress_public_key', 'decompress_public_key',
    'privkey_to_wif', 'privkey_from_wif',
    'publickey_to_address'
]

def compress_public_key(public_key):
    """Compresses a given uncompressed public key.

    :param public_key: the key to compress, as bytes
    :return: the compressed key, as bytes
    """
    if public_key[0] != 0x04 or len(public_key) != 65:
        raise ValueError('invalid uncompressed public key')
    # We take the y coordinate
    y = int.from_bytes(public_key, 'big')
    # And check its parity, to add the appropriate byte
    if y % 2:
        return b'\x03' + public_key[1:33]
    else:
        return b'\x02' + public_key[1:33]

_a = curve.curve.a()
_b = curve.curve.b()
_p = curve.curve.p()
_n = curve.order

def decompress_public_key(public_key):
    #print(public_key)
    if public_key[0] == 0x04 and len(public_key) == 65:
        x = string_to_number(public_key[1:33])
        y = string_to_number(public_key[33:65])
        if not point_is_valid(curve.generator, x, y):
            raise ValueError('invalid uncompressed public key')
        return public_key

    if public_key[0] not in (0x02, 0x03) or len(public_key) != 33:
        raise ValueError('invalid compressed public key')

    x = int.from_bytes(public_key[1:], 'big')
    #print(x ** 3 + _a * x + _b, _p)
    y = square_root_mod_prime((x ** 3 + _a * x + _b) % _p, _p)
    if not point_is_valid(curve.generator, x, y):
        raise ValueError('invalid public key')

    if (public_key[0] & 0x01) != (y & 0x01):
        y = _p - y

    return b'\x04' + public_key[1:] + number_to_string(y, _n)


# See: https://en.bitcoin.it/wiki/Wallet_import_format
def privkey_to_wif(privkey, prefix = b'\x80'):
    return base58.encode_check(prefix + privkey)

# See: https://en.bitcoin.it/wiki/Wallet_import_format
def privkey_from_wif(privkey, prefix = b'\x80'):
    key = base58.decode_check(privkey)
    if int.from_bytes(prefix, 'big') != key[0]:
        raise ValueError('wif private key does not match prefix')
    if len(key) == 33:
        if privkey[0] != '5':
            raise ValueError('uncompressed wif private key does not begin with 5')
        return key[1:]
    elif len(key) == 34:
        if key[-1] != 0x01:
            raise ValueError('compressed wif private key missing compression bit')
        if privkey[0] not in ('L', 'K'):
            raise ValueError('uncompressed wif private key does not begin with 5')
        return key[1:-1]
    raise ValueError('invalid wif private key')

def pubkeyhash_to_address(publickey_hash, version = 0x00):
    if version == 0x00:
        # A special case, otherwise converting 0x00 to bytes results in b''
        return base58.encode_check(b'\x00' + publickey_hash)
    else:
        if isinstance(version, int):
            version = version.to_bytes(base58.sizeof(version), 'big')
        return base58.encode_check(version + publickey_hash)

# See: https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
def publickey_to_address(publickey, version = 0x00):
    return pubkeyhash_to_address(hash160(publickey), version)

