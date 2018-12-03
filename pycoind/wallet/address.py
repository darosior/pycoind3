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

import os
import struct
import unicodedata
import scrypt
import uuid
import time
from Crypto.Cipher import AES

from .. import coins
from .. import util

from ..util.ecdsa import SECP256k1 as curve
from ..util.ecdsa.util import string_to_number, number_to_string, randrange
# from ..util.pyaes.aes import AES

__all__ = ['Address', 'EncryptedAddress', 'get_address', 'PrintedAddress']

class BaseAddress(object):
    def __init__(self, private_key, coin = coins.Bitcoin):
        self._private_key = private_key
        self._coin = coin

    coin = property(lambda s: s._coin)

    private_key = property(lambda s: s._private_key)

    @property
    def _privkey(self):
        'The binary representation of a private key.'

        if self.private_key is None:
            return None
        return util.key.privkey_from_wif(self.private_key)



class Address(BaseAddress):
    '''Wallet Address.

       Provide exactly one of:
         private_key    WIF encoded private key (compressed or uncompressed)
         public_key     binary public key (compressed or uncompressed)'''

    def __init__(self, public_key=None, private_key=None, coin=coins.Bitcoin):
        BaseAddress.__init__(self, private_key, coin)

        self._compressed = False

        if private_key:
            if public_key is not None:
                raise ValueError('cannot specify public_key and private_key')

            self._private_key = private_key

            # this is a compressed private key
            if private_key.startswith('L') or private_key.startswith('K'):
                self._compressed = True
            elif not private_key.startswith('5'):
                raise ValueError('unknown private key type: %r' % private_key[0])

            # determine the public key (internally, we only store uncompressed)
            secexp = string_to_number(util.key.privkey_from_wif(self._private_key))
            point = curve.generator * secexp
            public_key = _key_from_point(point, False)

        else:
            self._private_key = None

        if public_key:
            # we store the public key decompressed
            if public_key[0] == 0x04:
                if len(public_key) != 65:
                    raise ValueError('invalid uncompressed public key')
            elif public_key[0] in (0x02, 0x03):
                public_key = util.key.decompress_public_key(public_key)
                self._compressed = True
            else:
                raise ValueError('invalid public key')

            self._public_key = public_key

        # we got no parameters
        else:
            raise ValueError('no address parameters')

        # determine the address
        self._address = util.key.publickey_to_address(self.public_key, version = coin.address_version)

    @property
    def public_key(self):
        """
        Returns the public key in the appropriate format (whether compressed or not)
        """
        if self._compressed:
            return util.key.compress_public_key(self._public_key)
        return self._public_key

    address = property(lambda s: s._address)

    compressed = property(lambda s: s._compressed)

    @staticmethod
    def generate(compressed = True, coin = coins.Bitcoin):
        """
        Generates a private key from a CSRNG.
        
        :param compressed: Whether or not the public key should be compressed.
        :param coin: The network.
        :return: An instance of the Address class.
        """
        while True:
            seconds = int(time.time())
            entrop1 = util.sha256d(seconds.to_bytes(util.base58.sizeof(seconds), 'big'))
            entrop2 = util.sha256d(os.urandom(256))
            entrop3 = util.sha256d(uuid.uuid4().bytes)
            entropy = util.sha256d(entrop1 + entrop2 + entrop3)
            secexp = int.from_bytes(entropy, 'big')
            if secexp < curve.order:
                break
        key = number_to_string(secexp, curve.order)
        if compressed:
            key = key + b'\x01'
        return Address(private_key = util.key.privkey_to_wif(key), coin = coin)

    @staticmethod
    def from_binary(binary_key, compressed = True):
        '''Returns a key associated with a 32-byte key. This is useful for
           brain wallets or wallets generated from other sources of entropy.'''

        if len(binary_key) == 32:
            key = string_to_number(binary_key)
            if 1 <= key < curve.order:
                if compressed:
                    binary_key += chr(0x01)
                private_key = util.key.privkey_to_wif(binary_key)
                return Address(private_key = private_key)

        raise ValueError('invalid binary key')

    def decompress(self):
        'Returns the decompressed address.'

        if not self.compressed: return self

        if self.private_key:
            return Address(private_key = util.key.privkey_to_wif(self._privkey), coin = self.coin)

        if address.public_key:
            return Address(public_key = util.key.decompress_public_key(self.public_key), coin = self.coin)

        raise ValueError('address cannot be decompressed')

    def compress(self):
        'Returns the compressed address.'

        if self.compressed: return self

        if self.private_key:
            return Address(private_key = util.key.privkey_to_wif(self._privkey + b'\x01'), coin = self.coin)

        if self.public_key:
            return Address(public_key = util.key.compress_public_key(self.public_key), coin = self.coin)

        raise ValueError('address cannot be compressed')

    def encrypt(self, passphrase):
        'Return an encrypted address using  passphrase.'

        if self.private_key is None:
            raise ValueError('cannot encrypt address without private key')

        return _encrypt_private_key(self.private_key, passphrase, self.coin)

    def sign(self, data):
        "Signs data with this address' private key."

        if self.private_key is None: raise Exception()
        pk = util.key.privkey_from_wif(self.private_key, self.coin.address_version)
        return util.ecc.sign(data, pk)

    def verify(self, data, signature):
        "Verifies the data and signature with this address' public key."

        if self.public_key is None: raise Exception()
        return util.ecc.verify(data, self._public_key, signature)

    def __str__(self):
        private_key = 'None'
        if self.private_key: private_key = '**redacted**'
        return '<Address address=%s public_key=%s private_key=%s>' % (self.address, self.public_key.encode('hex'), private_key)


class EncryptedAddress(BaseAddress):
    """
    Represents an address derived from a BIP38 encrypted private key (EC multiply or not).
    For more about BIP38 see https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
    """
    def __init__(self, private_key, coin = coins.Bitcoin):
        BaseAddress.__init__(self, private_key, coin)

        privkey = self._privkey
        if len(privkey) != 39 or privkey[0:2] not in (b'\x01\x42', b'\x01\x43'):
            raise ValueError('unsupported encrypted address')

        self._compressed = privkey[2] == int('e0', 16)

    # encrypted addresses don't use the standard wif prefix
    _privkey = property(lambda s: util.base58.decode_check(s.private_key))

    compressed = property(lambda s: s._compressed)

    @staticmethod
    def generate(passphrase, compressed = True, coin = coins.Bitcoin):
        'Generate a new random address encrypted with passphrase.'

        address = Address.generate(compressed, coin)
        return EncryptedAddress.encrypt_address(address, passphrase, compressed)

    def decrypt(self, passphrase):
        'Return a decrypted address of this address, using passphrase.'

        # what function do we use to decrypt?
        if self._privkey[1] == 0x42:
            return _decrypt_private_key(self.private_key, passphrase, self.coin)
        else:
            return _decrypt_printed_private_key(self.private_key, passphrase, self.coin)

    def __str__(self):
        return '<EncryptedAddress private_key=%s>' % self.private_key


class PrintedAddress(Address):
    """This should not be instantiated directly. Use:

          EncryptedAddress(printed_private_key).decrypt(passphrase)

       If Alice wishes Bob to create private keys for her, she can come up with
       a secure passphrase, which she uses to generate an intermediate code
       (EncryptedAddress.generate_intermediate_code) which can be given to Bob.
       Bob is no able to create new EncryptedPrintedAddresses, for which he can
       determine the address and public key, but is unable to determine the
       decrypted private key. He then provides Alice the encrypted private key,
       which Alice can then decrypt using her passphrase, to get the decrypted
       private key."""

    def __init__(self):
        raise ValueError('cannot instantiate a PrintedAddress')

    lot = property(lambda s: s._lot)
    sequence = property(lambda s: s._sequence)

    @staticmethod
    def generate_intermediate_code(passphrase, lot = None, sequence = None):
        '''Generates an intermediate code for generated printed addresses
           using passphrase and optional lot and sequence.'''

        return _generate_intermediate_code(passphrase, lot, sequence)

    @staticmethod
    def generate(intermediate_code, compressed, coin = coins.Bitcoin):
        'Generate a new random printed address for the intermediate_code.'
        return _generate_printed_address(intermediate_code, compressed, coin)

    @staticmethod
    def confirm(confirmation_code, passphrase, coin = coins.Bitcoin):
        "Confirm a passphrase decrypts a printed address' confirmation_code."

        return _check_confirmation_code(confirmation_code, passphrase, coin)


class EncryptedPrintedAddress(EncryptedAddress):
    """This should not be instantiated directly. Use:

          code = PrintedAddress.generate_intermediate_code(passphrase)
          PrintedAddress.generate(code)"""

    def __init__(self):
        raise ValueError('cannot instantiate an EncryptedPrintedAddress')

    public_key = property(lambda s: s._public_key)
    address = property(lambda s: s._address)

    confirmation_code = property(lambda s: s._confirmation_code)

    lot = property(lambda s: s._lot)
    sequence = property(lambda s: s._sequence)


class Confirmation(object):
    """This should not be instantiated directly. Use:

          PrintedAddress.confirm(confimation_code, passphrase)"""

    def __init__(self):
        raise ValueError('cannot instantiate a Confirmation')

    coin = property(lambda s: s._coin)

    address = property(lambda s: s._address)

    public_key = property(lambda s: s._public_key)
    compressed = property(lambda s: s._compressed)

    lot = property(lambda s: s._lot)
    sequence = property(lambda s: s._sequence)

    def __str__(self):
        return '<Confirmation address=%s lot=%s sequence=%s>' % (self.address, self.lot, self.sequence)


def _normalize_utf(text):
    """
    Encodes text in UTF-8 using "Normalization Form C"

    :param text: The text to encode
    :return: encoded text (as bytes)
    """

    return unicodedata.normalize('NFC', str(text)).encode('utf8')

def _encrypt_xor(a, b, aes):
    'Returns encrypt(a ^ b).'

    block = [(ord(a) ^ ord(b)) for (a, b) in zip(a, b)]
    return "".join(chr(c) for c in aes.encrypt(block))

def _decrypt_xor(a, b, aes):
    'Returns decrypt(a) ^ b)'

    a = [ord(c) for c in a]
    block = [(a ^ ord(b)) for (a, b) in zip(aes.decrypt(a), b)]
    return "".join(chr(c) for c in block)

def _encrypt_private_key(private_key, passphrase, coin = coins.Bitcoin):
    """
    Encrypts a private_key as specified in BIP38.

    :param private_key: The wif-encoded private key to encrypt, as str
    :param passphrase: The passphrase with which encrypt the private key
    :param coin: The network, Bitcoin by default
    :return: an instance of the EncryptedAddress class
    """
    # compute the flags
    flagbyte = b'\xc0'
    if private_key.startswith('L') or private_key.startswith('K'):
        flagbyte = b'\xe0'
    elif not private_key.startswith('5'):
        raise ValueError('unknown private key type')

    # compute the address, which is used for the salt
    address = Address(private_key = private_key, coin = coin)
    salt = util.sha256d(address.address.encode())[:4]

    # compute the key
    derived_key = scrypt.hash(_normalize_utf(passphrase), salt, 16384, 8, 8)
    (derived_half1, derived_half2) = (derived_key[:32], derived_key[32:])

    aes = AES.new(derived_half2)

    # encrypt the private key
    key  = address._privkey
    int1 = int.from_bytes(key[:16], 'big') ^ int.from_bytes(derived_half1[:16], 'big')
    int2 = int.from_bytes(key[16:32], 'big') ^ int.from_bytes(derived_half1[16:32], 'big')
    encrypted_half1 = aes.encrypt(int1.to_bytes(util.base58.sizeof(int1), 'big'))
    encrypted_half2 = aes.encrypt(int2.to_bytes(util.base58.sizeof(int2), 'big'))

    # encode it
    payload = util.base58.encode_check(b'\x01' + b'\x42' + flagbyte + salt + encrypted_half1 + encrypted_half2)

    return EncryptedAddress(payload, coin)


def _decrypt_private_key(private_key, passphrase, coin = coins.Bitcoin):
    """
    Decrypts a BIP38 encrypted private key

    :param private_key: The encrypted private key, as str
    :param passphrase: The passphrase with which was encrypted the key, as str
    :param coin: The network (Bitcoin by default)
    :return: an instance of the Address class
    """
    payload = util.base58.decode_check(private_key)
    if len(payload) != 39 or payload[:2] != b'\x01\x42':
        return None

    # Decoding the flags
    flagbyte = payload[2].to_bytes(util.base58.sizeof(payload[2]), 'big')
    compressed = flagbyte == b'\xe0'

    # The address
    salt = payload[3:7]
    encrypted = payload[7:39]

    # compute the key
    derived_key = scrypt.hash(_normalize_utf(passphrase), salt, 16384, 8, 8)
    (derived_half1, derived_half2) = (derived_key[0:32], derived_key[32:])

    aes = AES.new(derived_half2)

    # decrypt the payload
    decrypted_half1 = aes.decrypt(encrypted[:16])
    decrypted_half2 = aes.decrypt(encrypted[16:])

    # Decrypting the XOR
    privkey = int.from_bytes(decrypted_half1 + decrypted_half2, 'big') ^ int.from_bytes(derived_half1, 'big')
    privkey = privkey.to_bytes(util.base58.sizeof(privkey), 'big')

    # set the private key compressed bit if needed
    if compressed:
        privkey += b'\x01'

    # check the decrypted private key is correct (otherwise, wrong password)
    address = Address(private_key = util.key.privkey_to_wif(privkey), coin = coin)
    if util.sha256d(address.address.encode())[:4] != salt:
        return None

    return Address(private_key = address.private_key, coin = coin)

def _key_from_point(point, compressed):
    'Converts a point into a key.'
    key = b'\x04' + number_to_string(point.x(), curve.order) + number_to_string(point.y(), curve.order)

    if compressed:
        key = util.key.compress_public_key(key)

    return key

def _key_to_point(key):
    'Converts a key to an EC Point.'
    key = util.key.decompress_public_key(key)
    x = int.from_bytes(key[1:33], 'big')
    y = int.from_bytes(key[33:65], 'big')
    return util.ecc.point(x, y)

def _generate_intermediate_code(passphrase, lot = None, sequence = None):
    """
    Generates an intermediate code for EC multiply BIP38 encryption.
    See https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki for details and parameters.
    """
    if (lot is None) ^ (sequence is None):
        raise ValueError('must specify both or neither of lot and sequence')

    if lot and not (0 <= lot <= 0xfffff):
        raise ValueError('lot is out of range')

    if sequence and not (0 <= sequence <= 0xfff):
        raise ValueError('sequence is out of range')

    # compute owner salt and entropy
    if lot is None:
        owner_salt = os.urandom(8)
        owner_entropy = owner_salt
        prefactor = scrypt.hash(_normalize_utf(passphrase), owner_salt, 16384, 8, 8, 32)
        pass_factor = int.from_bytes(prefactor, 'big')
    else:
        owner_salt = os.urandom(4)
        lot_sequence = struct.pack('>I', (lot << 12) | sequence)
        owner_entropy = owner_salt + lot_sequence
        prefactor = scrypt.hash(_normalize_utf(passphrase), owner_salt, 16384, 8, 8, 32)
        pass_factor = int.from_bytes(util.hash.sha256d(prefactor + owner_entropy), 'big')

    # compute the public point
    point = curve.generator * pass_factor
    pass_point = _key_from_point(point, compressed=True)

    prefix = b'\x2c\xe9\xb3\xe1\xff\x39\xe2\x53' if lot is None else b'\x2c\xe9\xb3\xe1\xff\x39\xe2\x51'

    # make a nice human readable string, beginning with "passphrase"
    return util.base58.encode_check(prefix + owner_entropy + pass_point)

def _generate_confirmation_code(flagbyte, ownerentropy, factorb, derived_half1, derived_half2, address_hash):
    """
    Generates a confirmation code for the owner, as specified in BIP38.
    See https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki for more about the process and params.

    :return: The confirmation code (as str).
    """
    # generate the confirmation code point
    point = curve.generator * factorb
    pointb = _key_from_point(point, True)

    # XOR it
    pointb_prefix = pointb[0] ^ (derived_half2[31] & 0x01)

    # Encryption of pointb
    aes = AES.new(derived_half2)
    intbx1 = int.from_bytes(pointb[1:17], 'big') ^ int.from_bytes(derived_half1[:16], 'big')
    intbx2 = int.from_bytes(pointb[17:], 'big') ^ int.from_bytes(derived_half1[16:], 'big')
    pointbx1 = aes.encrypt(intbx1.to_bytes(util.base58.sizeof(intbx1), 'big'))
    pointbx2 = aes.encrypt(intbx2.to_bytes(util.base58.sizeof(intbx2), 'big'))
    encrypted_pointb = pointb_prefix.to_bytes(util.base58.sizeof(pointb_prefix), 'big') + pointbx1 + pointbx2

    return util.base58.encode_check(b'\x64\x3b\xf6\xa8\x9a' + flagbyte.to_bytes(util.base58.sizeof(flagbyte), 'big')
                                    + address_hash + ownerentropy + encrypted_pointb)


def _generate_printed_address(intermediate_code, compressed, coin = coins.Bitcoin):
    """
    Generates a BIP38 encrypted private key with EC multiply.
    See https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki for more about the process.

    :param intermediate_code: The pass used to encrypt the key and generated by the owner (bytes).
    :param compressed: Whether or not this key will be used to generate a compressed public key (bool).
    :param coin: The network, Bitcoin by default.
    :return: An instance of the Encrypted_address class.
    """
    payload = util.base58.decode_check(intermediate_code)

    if len(payload) != 49:
        raise ValueError('invalid intermediate code')
    if payload[0:7] != b'\x2c\xe9\xb3\xe1\xff\x39\xe2':
        raise ValueError('invalid intermediate code prefix')

    # de-serialize the payload
    magic_suffix = payload[7]
    owner_entropy = payload[8:16]
    pass_point = payload[16:49]

    # prepare the flags
    flagbyte = 0
    if compressed:
        flagbyte |= 0x20

    # if we have a lot and sequence, determine them and set the flags
    lot = None
    sequence = None
    if magic_suffix == 0x51:
        flagbyte |= 0x04
        lot_sequence = struct.unpack('>I', owner_entropy[4:8])[0]
        lot = lot_sequence >> 12
        sequence = lot_sequence & 0xfff
    elif magic_suffix != 0x53:
        raise ValueError('invalid intermediate code prefix')

    # generate the random seedb
    seedb = os.urandom(24)
    factorb = string_to_number(util.sha256d(seedb))

    # compute the public point (and address)
    point = _key_to_point(pass_point) * factorb
    public_key = _key_from_point(point, compressed)

    generated_address = util.key.publickey_to_address(public_key, coin.address_version)

    address_hash = util.sha256d(generated_address.encode())[:4]

    # key for encrypting the seedb (from the public point)
    salt = address_hash + owner_entropy
    derived_key = scrypt.hash(pass_point, salt, 1024, 1, 1, 64)
    (derived_half1, derived_half2) = (derived_key[:32], derived_key[32:])

    aes = AES.new(derived_half2)

    int1 = int.from_bytes(seedb[:16], 'big') ^ int.from_bytes(derived_half1[:16], 'big')
    encrypted_half1 = aes.encrypt(int1.to_bytes(util.base58.sizeof(int1), 'big'))
    int2 = int.from_bytes(encrypted_half1[8:16] + seedb[16:24], 'big') ^ int.from_bytes(derived_half1[16:], 'big')
    encrypted_half2 = aes.encrypt(int2.to_bytes(util.base58.sizeof(int2), 'big'))

    # final binary private key
    payload = (b'\x01\x43' + flagbyte.to_bytes(util.base58.sizeof(flagbyte), 'big') +
               address_hash + owner_entropy + encrypted_half1[0:8] + encrypted_half2)
    private_key = util.base58.encode_check(payload)

    confirmation_code = _generate_confirmation_code(flagbyte, owner_entropy, factorb, derived_half1, derived_half2, address_hash)

    # wrap it up in a nice object
    self = EncryptedPrintedAddress.__new__(EncryptedPrintedAddress)
    BaseAddress.__init__(self, private_key = private_key, coin = coin)

    self._public_key = public_key
    self._address = generated_address

    self._lot = lot
    self._sequence = sequence

    self._confirmation_code = confirmation_code

    return self


def _check_confirmation_code(confirmation_code, passphrase, coin = coins.Bitcoin):
    """
    Verifies if the confirmation code matches the passphrase by recalculating the address.

    :return: An instance of the Confirmation class.
    """
    payload = util.base58.decode_check(confirmation_code)
    if payload[:5] != b'\x64\x3b\xf6\xa8\x9a':
        raise ValueError('invalid confirmation code prefix')

    # de-serialize the payload
    flagbyte = payload[5]
    address_hash = payload[6:10]
    owner_entropy = payload[10:18]
    encrypted_pointb = payload[18:]

    # check for compressed flag
    compressed = False
    if flagbyte & 0x20:
        compressed = True

    # check for a lot and sequence
    lot = None
    sequence = None
    owner_salt = owner_entropy
    if flagbyte & 0x04:
        lot_sequence = struct.unpack('>I', owner_entropy[4:8])[0]
        lot = lot_sequence >> 12
        sequence = lot_sequence & 0xfff
        owner_salt = owner_entropy[:4]

    prefactor = scrypt.hash(_normalize_utf(passphrase), owner_salt, 16384, 8, 8, 32)
    if lot is None:
        pass_factor = int.from_bytes(prefactor, 'big')
    else:
        pass_factor = int.from_bytes(util.hash.sha256d(prefactor + owner_entropy), 'big')

    # determine the passpoint
    point = curve.generator * pass_factor
    pass_point = _key_from_point(point, True)

    # derive the key that was used to encrypt the pointb
    salt = address_hash + owner_entropy
    derived_key = scrypt.hash(pass_point, salt, 1024, 1, 1, 64)
    (derived_half1, derived_half2) = (derived_key[:32], derived_key[32:])

    aes = AES.new(derived_half2)

    # decrypt the pointb by doing the reverse scheme done in generate_confirmation_code :
    # The prefix
    pointb_prefix = encrypted_pointb[0] ^ (derived_half2[31] & 0x01)
    # The AES decryption
    pointbx1 = aes.decrypt(encrypted_pointb[1:17])
    pointbx2 = aes.decrypt(encrypted_pointb[17:])
    # The XOR
    intb1 = int.from_bytes(pointbx1, 'big') ^ int.from_bytes(derived_half1[:16], 'big')
    intb2 = int.from_bytes(pointbx2, 'big') ^ int.from_bytes(derived_half1[16:], 'big')
    # We convert it to bytes
    pointb1 = intb1.to_bytes(util.base58.sizeof(intb1), 'big')
    pointb2 = intb2.to_bytes(util.base58.sizeof(intb2), 'big')
    # And append everything to get the point
    pointb = pointb_prefix.to_bytes(util.base58.sizeof(pointb_prefix), 'big') + pointb1 + pointb2

    # compute the public key (and address)
    point = _key_to_point(pointb) * pass_factor
    public_key = _key_from_point(point, compressed)

    address = util.key.publickey_to_address(public_key, coin.address_version)

    # verify the checksum
    if util.sha256d(address.encode())[:4] != address_hash:
        raise ValueError('invalid passphrase')

    # wrap it up in a nice object
    self = Confirmation.__new__(Confirmation)

    self._public_key = public_key
    self._address = address
    self._compressed = compressed

    self._lot = lot
    self._sequence = sequence

    self._coin = coin

    return self


def _decrypt_printed_private_key(private_key, passphrase, coin = coins.Bitcoin):
    """
    Decrypts an EC-multiply BIP38 encrypted private key.

    :param private_key: The encrypted private key.
    :param passphrase: The passphrase with which the key was encrypted
    :param coin: The network, Bitcoin by default.
    :return: An instance of the PrintedAddress class.
    """
    payload = util.base58.decode_check(private_key)

    if payload[:2] != b'\x01\x43':
        raise ValueError('invalid printed address private key prefix')

    if len(payload) != 39:
        raise ValueError('invalid printed address private key length')

    # de-serialize the payload
    flagbyte = payload[2]
    address_hash = payload[3:7]
    owner_entropy = payload[7:15]
    encrypted_quarter1 = payload[15:23]
    encrypted_half2 = payload[23:39]

    # check for compressed flag
    compressed = False
    if flagbyte & 0x20:
        compressed = True

    # check for lot and sequence
    (lot, sequence) = (None, None)
    owner_salt = owner_entropy
    if flagbyte & 0x04:
        lot_sequence = struct.unpack('>I', owner_entropy[4:8])[0]
        lot = lot_sequence >> 12
        sequence = lot_sequence & 0xfff
        owner_salt = owner_entropy[:4]

    prefactor = scrypt.hash(_normalize_utf(passphrase), owner_salt, 16384, 8, 8, 32)
    if lot is None:
        pass_factor = int.from_bytes(prefactor, 'big')
    else:
        pass_factor = int.from_bytes(util.hash.sha256d(prefactor + owner_entropy), 'big')

    # compute the public point
    point = curve.generator * pass_factor
    pass_point = _key_from_point(point, True)

    # derive the key that was used to encrypt the seedb; based on the public point
    derived_key = scrypt.hash(pass_point, address_hash + owner_entropy, 1024, 1, 1, 64)
    (derived_half1, derived_half2) = (derived_key[:32], derived_key[32:])

    aes = AES.new(derived_half2)

    # decrypt the seedb (it was nested, so we work backward)
    int_half2 = int.from_bytes(aes.decrypt(encrypted_half2), 'big') ^ int.from_bytes(derived_half1[16:], 'big')
    decrypted_half2 = int_half2.to_bytes(util.base58.sizeof(int_half2), 'big')
    encrypted_half1 = encrypted_quarter1 + decrypted_half2[:8]
    int_half1 = int.from_bytes(aes.decrypt(encrypted_half1), 'big') ^ int.from_bytes(derived_half1[:16], 'big')
    decrypted_half1 = int_half1.to_bytes(util.base58.sizeof(int_half1), 'big')

    # compute the seedb
    seedb = decrypted_half1 + decrypted_half2[8:16]
    factorb = int.from_bytes(util.sha256d(seedb), 'big')

    # compute the secret exponent
    secexp = (factorb * pass_factor) % curve.order

    # convert it to a private key
    private_key = number_to_string(secexp, curve.order)
    if compressed:
        private_key += b'\x01'

    # wrap it up in a nice object
    self = PrintedAddress.__new__(PrintedAddress)
    Address.__init__(self, private_key = util.key.privkey_to_wif(private_key), coin = coin)

    self._lot = lot
    self._sequence = sequence

    # verify the checksum
    if address_hash != util.sha256d(self.address.encode())[:4]:
        raise ValueError('incorrect passphrase')

    return self


def get_address(private_key, passphrase = None, coin = coins.Bitcoin):
    '''Detects the type of private key uses the correct class to instantiate
       an Address, optionally decrypting it with passphrase.'''

    # unencrypted
    if private_key[0] in ('5', 'L', 'K'):
        return Address(private_key = private_key, coin = coin)

    # encrypted
    if private_key.startswith('6P'):
        address = EncryptedAddress(private_key = private_key, coin = coin)

        # decrypt it if we have a passphrase
        if passphrase:
            address = address.decrypt(passphrase)

        return address

    return None


