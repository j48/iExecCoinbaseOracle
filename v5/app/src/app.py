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

# https://docs.pro.coinbase.com/#recovering-signatory
coinbase_url = 'https://api.pro.coinbase.com/oracle'
coinbase_public_key = '0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC'
coinbase_coins = ['BTC', 'ETH', 'DAI', 'REP', 'ZRX', 'BAT', 'KNC', 'LINK']

openoracle_abi_types = ['string', 'uint256', 'string', 'uint256']

iexec_root = '/'
iexec_in = os.getenv('IEXEC_IN') or f'{iexec_root}iexec_in'
iexec_out = os.getenv('IEXEC_OUT') or f'{iexec_root}iexec_out'
iexec_dataset_filename = os.getenv('IEXEC_DATASET_FILENAME') or 'coinbase_api_key.json'
iexec_computed_filename = 'computed.json'
iexec_stdout_filename = 'log.txt'


# https://developers.coinbase.com/api/v2?shell#api-key
class CoinbaseProSignedAPI:

    def __init__(self, key, secret, passphrase):
        self.key = key
        self.secret = secret
        self.passphrase = passphrase

        self.public_key = coinbase_public_key
        self.url = coinbase_url
        self.coins = coinbase_coins

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
                        self.error = 'API result JSON incomplete, must include messages and signatures'
                else:
                    self.error = f"API error status code ({result.status_code})"
            except (Exception, ConnectionError) as e:
                self.error = e
        else:
            self.error = f"invalid coin, choose from {self.coins}"


def create_callback(msg_hex, sig_hex):
    msg_bytes = Web3.toBytes(hexstr=msg_hex)
    sig_bytes = Web3.toBytes(hexstr=sig_hex)
    ec_recover_types = ['bytes', 'bytes']
    ec_recover_args = (msg_bytes, sig_bytes)
    encoded_abi = eth_abi.encode_abi(ec_recover_types, ec_recover_args)

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


def read_credentials_file(f):
    try:
        with open(f, 'r') as file:
            try:
                credentials_file = json.load(file)
                if 'key' and 'secret' and 'passphrase' in credentials_file:
                    return credentials_file
                else:
                    return {'error': 'credentials incomplete'}
            except (Exception, TypeError):
                return {'error': 'invalid credentials JSON format'}
    except (Exception, FileNotFoundError):
        return {'error': 'credentials file not found'}


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
    user_input = sys.argv[1] if len(sys.argv) > 1 else None
    stdout_print(f"user input: {user_input}")

    # modified for v5 & ERC2362, stdout/log for TEE is optional
    callback = None

    try:
        if not user_input:
            raise Exception("no user input found")

        credentials = read_credentials_file(f"{iexec_in}/{iexec_dataset_filename}")

        if 'error' in credentials:
            raise Exception(credentials['error'])

        coinbase_api = CoinbaseProSignedAPI(credentials['key'], credentials['secret'], credentials['passphrase'])

        coin = user_input.upper()
        coinbase_api.call(coin)

        if coinbase_api.error:
            raise Exception(coinbase_api.error)

        for i, message in enumerate(coinbase_api.result['messages']):
            message_bytes = Web3.toBytes(hexstr=message)
            message_decoded = eth_abi.decode_abi(openoracle_abi_types, message_bytes)

            coin_decoded = message_decoded[2].upper()

            if coin != coin_decoded:
                continue

            ecdsa_signature = coinbase_api.result['signatures'][i]

            if not verify_signature(message, ecdsa_signature, coinbase_api.public_key):
                callback = create_callback(message, "0x0")  # return invalid sig?
                raise Exception("*INVALID SIGNATURE FOR API RESULT*")

            stdout_print(f"*verified API result for {coin}*")

            callback = create_callback(message, ecdsa_signature)
            break

    except Exception as error:
        stdout_print(f"ERROR: {error}")

    if not callback:
        # general error
        error_args = ("error", 0, "", 0)
        error_bytes = eth_abi.encode_abi(openoracle_abi_types, error_args)
        error_hex = Web3.toHex(error_bytes)
        callback = create_callback(error_hex, "0x0")

    stdout_print(f"callback: {callback}")
    stdout_print(f"updating compute JSON with callback...")

    write_callback(callback, f'{iexec_out}/{iexec_computed_filename}')

    stdout_print(F"DONE! - {str(time.time())}")
