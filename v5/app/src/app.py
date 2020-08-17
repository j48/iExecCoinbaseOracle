import sys
import os
import time
import requests
import json
import base64
import hashlib
import hmac
import eth_abi
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.auto import w3
from contextlib import redirect_stdout

iexec_in = os.getenv('IEXEC_IN')
iexec_out = os.getenv('IEXEC_OUT')
iexec_dataset_filename = 'coinbase_api_key.json'
iexec_computed_filename = 'computed.json'
iexec_stdout_filename = 'log.txt'


# https://developers.coinbase.com/api/v2?shell#api-key
class CoinbaseProSignedAPI:

    coins = ['BTC', 'ETH', 'DAI', 'REP', 'ZRX', 'BAT', 'KNC', 'LINK', 'COMP']

    # https://docs.pro.coinbase.com/#recovering-signatory
    url = 'https://api.pro.coinbase.com/oracle'
    public_key = '0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC'

    def __init__(self, key, secret, passphrase):
        self.key = key
        self.secret = secret
        self.passphrase = passphrase

        self.result = {}
        self.error = None

    def _authenticate(self, request):
        timestamp = str(time.time())
        msg = timestamp + request.method.upper() + request.path_url + (request.body or '')
        signature = hmac.new(base64.b64decode(self.secret), msg.encode('utf-8'), hashlib.sha256)
        signature_b64 = base64.b64encode(signature.digest())

        request.headers.update({
            'CB-ACCESS-KEY': self.key,
            'CB-ACCESS-SIGN': signature_b64,
            'CB-ACCESS-PASSPHRASE': self.passphrase,
            'CB-ACCESS-TIMESTAMP': timestamp,
            'Content-Type': 'application/json'
        })

        return request

    def call(self, c):
        # currently JSON returned with all coins (may change?)
        if c in self.coins:
            try:
                coin_url = self.url
                result = requests.get(coin_url, auth=self._authenticate)
                if result.status_code == 200:
                    if 'messages' and 'signatures' in result.json():
                        self.result = result.json()
                    else:
                        self.error = 7
                else:
                    self.error = 6
            except (Exception, ConnectionError) as e:
                self.error = 8
        else:
            self.error = 5


class ErrorCallback(Exception):
    # codes for callback, messages for debug
    messages = {
        1: 'no user input found',
        2: 'credentials file not found or corrupted',
        3: 'invalid dataset format',
        4: 'credentials incomplete',
        5: 'invalid coin',
        6: 'non 200 API error status code',
        7: 'API result JSON incomplete, must include messages and signatures',
        8: 'general API error',
        9: 'invalid signature',
        11: 'coin not in API results'
    }

    def __init__(self, code):
        self.code = code
        self.msg = self.messages[self.code]

    def __str__(self):
        return repr(self.msg)


def create_callback(msg_hex, sig_hex):
    msg_bytes = Web3.toBytes(hexstr=msg_hex)
    sig_bytes = Web3.toBytes(hexstr=sig_hex)
    ec_recover_args = (msg_bytes, sig_bytes)
    encoded_abi = eth_abi.encode_abi(['bytes', 'bytes'], ec_recover_args)

    return Web3.toHex(encoded_abi)


def write_callback(cb, loc):
    # allow for updating file
    try:
        with open(loc, 'r') as file:
            compute_json = json.load(file)
    except FileNotFoundError:
        compute_json = {}

    compute_json['callback-data'] = cb

    with open(loc, 'w') as file:
        json.dump(compute_json, file, indent=2)


def read_dataset_file(dsf, kind='json'):
    try:
        with open(dsf, 'r') as dataset_file:
            if kind == 'json':
                return json.load(dataset_file)
            else:
                return {'error': 3}
    except (Exception, FileNotFoundError):
        return {'error': 2}


def process_dataset(cj):
    try:
        keys = {'key': cj['key'], 'secret': cj['secret'], 'passphrase': cj['passphrase']}
        return keys
    except KeyError:
        return {'error': 4}


def verify_signature(msg_hex, sig_hex, verify_signer):
    sig = Web3.toBytes(hexstr=sig_hex)
    v, r, s = Web3.toInt(sig[-1]), sig[:32], sig[32:64]

    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html?highlight=verify#verify-a-message-from-message-hash
    message_hash = Web3.keccak(hexstr=msg_hex)
    msg = encode_defunct(message_hash)
    msg_signer = w3.eth.account.recover_message(msg, vrs=[v, r, s])

    if msg_signer.upper() == verify_signer.upper():
        return True


def stdout_print(txt):
    with open(f"{iexec_out}/{iexec_stdout_filename}", 'a') as file:
        with redirect_stdout(file):
            print(f"{txt}")


if __name__ == "__main__":
    stdout_print(f"STARTING - {str(time.time())}")

    try:
        user_input = sys.argv[1]
    except IndexError:
        user_input = None

    stdout_print(f"user input: {user_input}")

    # modified for v5 & ERC2362, stdout/log for TEE for debug, error code for callback
    callback = None

    try:
        if not user_input:
            raise ErrorCallback(1)

        dataset = read_dataset_file(f"{iexec_in}/{iexec_dataset_filename}", 'json')

        if 'error' in dataset:
            raise ErrorCallback(dataset['error'])

        credentials = process_dataset(dataset)

        if 'error' in credentials:
            raise ErrorCallback(credentials['error'])

        coinbase_api = CoinbaseProSignedAPI(credentials['key'], credentials['secret'], credentials['passphrase'])

        coin = user_input.upper()
        coinbase_api.call(coin)

        if coinbase_api.error:
            raise ErrorCallback(coinbase_api.error)

        for i, message in enumerate(coinbase_api.result['messages']):
            message_bytes = Web3.toBytes(hexstr=message)
            message_decoded = eth_abi.decode_abi(['string', 'uint256', 'string', 'uint256'], message_bytes)

            coin_decoded = message_decoded[2].upper()

            if coin != coin_decoded:
                continue

            ecdsa_signature = coinbase_api.result['signatures'][i]

            if not verify_signature(message, ecdsa_signature, coinbase_api.public_key):
                callback = create_callback(message, "0x0")  # return invalid sig?
                raise ErrorCallback(9)

            stdout_print(f"*verified API result for {coin} found*")

            callback = create_callback(message, ecdsa_signature)
            break

        if not callback:
            raise ErrorCallback(11)

    except ErrorCallback as e_callback:
        stdout_print(f"ERROR ({e_callback.code}): {e_callback}")

        error_args = ("error", 0, "", e_callback.code)
        error_bytes = eth_abi.encode_abi(['string', 'uint256', 'string', 'uint256'], error_args)
        error_hex = Web3.toHex(error_bytes)

        callback = create_callback(error_hex, "0x0")

    stdout_print(f"callback: {callback}")

    write_callback(callback, f'{iexec_out}/{iexec_computed_filename}')

    stdout_print(F"DONE! - {str(time.time())}")
