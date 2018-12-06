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


from . import coin
from .. import util
import binascii

__all__ = ['Insacoin']

class Insacoin(coin.Coin):
    name = "insacoin"

    # https://github.com/litecoin-project/litecoin/blob/master-0.8/src/main.cpp#L1085
    @staticmethod
    def block_creation_fee(block):
        return (42 * 100000000) >> (block.height // 840000)

    @staticmethod
    def proof_of_work(block_header):
        block_header = block_header[:80]
        return util.scrypt(block_header, block_header, 1024, 1, 1, 32)

    symbols = [ 'ISC' ]
    symbol = symbols[0]

    # See: https://github.com/litecoin-project/litecoin/blob/master-0.8/src/net.cpp#L1194
    dns_seeds = [
        ("dnsseed.chaingeit.net", 7333),
    ]

    port = 7333
    rpc_port = 7332

    genesis_version = 1
    genesis_block_hash = binascii.unhexlify('12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2')
    genesis_merkle_root = binascii.unhexlify('97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9')
    genesis_timestamp = 1317972665
    genesis_bits = 504365040
    genesis_nonce = 4294967295
    
    # https://github.com/litecoin-project/litecoin/blob/master-0.8/src/main.cpp#L3082
    magic = "\xfd\xc2\xb8\xdd"

    alert_public_key = binascii.unhexlify('04978a60a55a728d1d12608d432b33d5cce8405a4d39a7b50aa9d9e8a22e62b74e9882a52108072104ad3d0356e457751879dfbef27d051ce421968259184482fc')
    address_version = 0x66
    secret_key = 0xb0
    
    block_height_guess = [
    ]

class InsacoinTestnet(Insacoin):

    port = 19333
    rpc_port = 19332

    magic = "\xfc\xc1\xb7\xdc"

    alert_public_key = binascii.unhexlify('04978a60a55a728d1d12608d432b33d5cce8405a4d39a7b50aa9d9e8a22e62b74e9882a52108072104ad3d0356e457751879dfbef27d051ce421968259184482fc')
