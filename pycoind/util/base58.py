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


from .hash import sha256d
from math import log


# From https://github.com/darosior/bitcoineasy/blob/master/bitcoineasy/utils.py
def sizeof(n):
    """get the size in bytes of an integer, https://stackoverflow.com/questions/14329794/get-size-of-integer-in-python

    :param n: the integer to get the size from

    :return: the size in bytes of the int passed as the first parameter.
    """
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


# From https://github.com/darosior/bitcoineasy/blob/master/bitcoineasy/utils.py
def b58encode(payload):
    """Takes a number (int or bytes) and returns its base58_encoding.

    :param payload: The data to encode, can be bytes or int

    :return: the number passed as first parameter as a base58 encoded str.
    """
    if isinstance(payload, bytes):
        n = int.from_bytes(payload, 'big')
    elif isinstance(payload, int):
        n = payload
    else:
        raise ValueError('b58encode takes bytes or int')

    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    x = n % 58
    rest = n // 58
    if rest == 0:
        return alphabet[x]
    else:
        return b58encode(rest) + alphabet[x]


def b58decode(string):
    """Takes a base58-encoded number and returns it in base10.

    :param string: the number to base58_decode (as str).

    :return: the number passed as first parameter, base10 encoded.
    """
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # Populating a dictionary with base58 symbol chart
    dict = {}
    k = 0
    for i in alphabet:
        dict[i] = k
        k += 1
    n = 0  # Result
    pos = 0  # Cf https://www.dcode.fr/conversion-base-n
    for i in string:
        for y in alphabet:
            if i == y:
                n = n * 58 + dict[i]
        pos += 1
    return n


def encode_check(payload):
    """Returns the base58 encoding with a 4-byte checksum.

    :param payload: The data (as bytes) to encode.
    """
    checksum = sha256d(payload)[:4]
    if payload[0] == 0x00:
        # Again, the leading 0 problem which results in nothing during int conversion
        return b58encode(b'\x00') + b58encode(payload + checksum)
    else:
        return b58encode(payload + checksum)

def decode_check(string):
    """Returns the base58 decoded value, verifying the checksum.

    :param string: The data to decode, as a string.
    """
    number = b58decode(string)
    # Converting to bytes in order to verify the checksum
    payload = number.to_bytes(sizeof(number), 'big')
    if payload and sha256d(payload[:-4])[:4] == payload[-4:]:
        return payload[:-4]
    else:
        return None

