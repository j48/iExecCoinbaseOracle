import base64
import hashlib
import hmac
import sys
import time
import requests
import json
import web3._utils.abi as eth_abi
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.auto import w3
from contextlib import redirect_stdout

# https://docs.pro.coinbase.com/#recovering-signatory
COINBASE_ORACLE_URL = 'https://api.pro.coinbase.com'
COINBASE_ORACLE_PUBLIC_KEY = '0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC'

root = '/'
input_dir = f'{root}iexec_in/'
output_dir = f'{root}scone/'
callback_file = 'callback.iexec'
determinism_file = 'determinism.iexec'
sgx_file = 'coinbase.json'
stdout_file = 'stdout.txt'


# https://developers.coinbase.com/api/v2?shell#api-key
class CoinbaseProAPI:

    def __init__(self, url, key, secret, passphrase):
        self.api_url = url
        self.api_key = key
        self.api_secret = secret
        self.passphrase = passphrase

    def authenticate(self, request):
        timestamp = str(time.time())
        msg = timestamp + request.method.upper() + request.path_url + (request.body or '')
        signature = hmac.new(base64.b64decode(self.api_secret), msg.encode('utf-8'), hashlib.sha256)
        signature_b64 = base64.b64encode(signature.digest())

        request.headers.update({
            'CB-ACCESS-KEY': self.api_key,
            'CB-ACCESS-SIGN': signature_b64,
            'CB-ACCESS-PASSPHRASE': self.passphrase,
            'CB-ACCESS-TIMESTAMP': timestamp,
            'Content-Type': 'application/json'
        })

        return request

    def call(self):
        return requests.get(self.api_url, auth=self.authenticate)


def decode_message(t, m):
    mb = Web3.toBytes(hexstr=m)

    abi_decoder = eth_abi.codec.ABIDecoder(eth_abi.default_registry)

    return abi_decoder.decode_abi(t, mb)


def get_message_signer(m, vrs):
    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html?highlight=verify#verify-a-message-from-message-hash
    message_hash = Web3.keccak(hexstr=m)
    msg = encode_defunct(message_hash)

    return w3.eth.account.recover_message(msg, vrs=vrs)


def create_callback(m, sig):
    message_bytes = Web3.toBytes(hexstr=m)
    sig_bytes = Web3.toBytes(hexstr=sig)
    ec_recover_args = (message_bytes, sig_bytes)
    ec_recover_types = ['bytes', 'bytes']

    abi_encoder = eth_abi.codec.ABIEncoder(eth_abi.default_registry)

    return Web3.toHex(abi_encoder.encode_abi(ec_recover_types, ec_recover_args))


def sig2vrs(sig_h):
    sig = Web3.toBytes(hexstr=sig_h)

    return Web3.toInt(sig[-1]), sig[:32], sig[32:64]


def write_callback(cb, loc):
    with open(loc, 'w') as file:
        file.write(cb)


def write_determinism(loc, cb=None):
    if not cb:
        cb = Web3.toHex(text="error")

    determinism = Web3.keccak(hexstr=cb).hex()

    with open(loc, 'w') as file:
        file.write(determinism)


def read_sgx_file(f):
    try:
        with open(f, 'r') as file:
            try:
                return json.load(file)
            except (Exception, TypeError):
                return 1
    except (Exception, FileNotFoundError):
        return 0


def stdout_print(t):
    with open(f"{output_dir}{stdout_file}", 'a') as f:
        with redirect_stdout(f):
            print(f"{t}")


def main(coin):
    coinbase_credentials = read_sgx_file(f"{input_dir}{sgx_file}")
    stdout_print(f"SGX file: {sgx_file}")

    if coinbase_credentials == 0:
        stdout_print('SGX file not found')
        return
    elif coinbase_credentials == 1:
        stdout_print('invalid SGX file format')
        return

    try:
        api_key = coinbase_credentials['key']
        api_secret = coinbase_credentials['secret']
        api_passphrase = coinbase_credentials['passphrase']
    except (Exception, TypeError):
        stdout_print('SGX file invalid JSON')
        return

    api_types = ['string', 'uint256', 'string', 'uint256']

    # currently API just returns values in same call
    url = COINBASE_ORACLE_URL + '/oracle'
    stdout_print(f"oracle API URL: {url}")

    coinbase_api = CoinbaseProAPI(url, api_key, api_secret, api_passphrase)

    r = coinbase_api.call()

    stdout_print(f"oracle response: {r.text}")

    if r.status_code == 200:
        message = None
        ecdsa_signature = None

        result = r.json()

        try:
            for i, entry in enumerate(result['prices']):
                stdout_print(f"Coin: {entry}")

                if entry.lower() == coin.lower():
                    stdout_print("*COIN FOUND*")
                    message = result['messages'][i]
                    ecdsa_signature = result['signatures'][i]
                    break

                else:
                    stdout_print("skipping...")

        except Exception as e:
            stdout_print(f"error: {e}")

        if message:
            stdout_print(f"message: {message}")
            stdout_print(f"ECDSA signature: {ecdsa_signature}")

            v, r, s = sig2vrs(ecdsa_signature)
            stdout_print(f"v: {v}")
            stdout_print(f"r: {Web3.toHex(r)}")
            stdout_print(f"s: {Web3.toHex(s)}")

            stdout_print(f"coinbase public key: {COINBASE_ORACLE_PUBLIC_KEY}")

            signer = get_message_signer(message, [v, r, s])

            if signer.lower() == COINBASE_ORACLE_PUBLIC_KEY.lower():
                stdout_print(f"*MESSAGE VERIFIED*")

                decoded_message = decode_message(api_types, message)
                stdout_print(f"decoded message: {decoded_message}")

                stdout_print(f"*CREATING CALLBACK FOR DORACLE SMARTCONTRACT*")
                return create_callback(message, ecdsa_signature)

            else:
                stdout_print(f"*MESSAGE FAILED VERIFICATION*")
        else:
            stdout_print(f"*COIN NOT FOUND*")
    else:
        stdout_print(f"API error ({r.status_code})")

    return False


# user input "ETH" or "BTC"
if __name__ == "__main__":
    valid_input = ['BTC', 'ETH', 'DAI', 'REP', 'ZRX', 'BAT', 'KNC', 'LINK']

    user_input = sys.argv[1] if len(sys.argv) > 1 else None

    if user_input:
        stdout_print(f"user input: {user_input}")
        if user_input.upper() in valid_input:
            callback = main(user_input)
            if callback:
                stdout_print(f"callback: {callback}")
                stdout_print(f"writing callback...")
                write_callback(callback, f'{output_dir}{callback_file}')

                stdout_print(f"writing determinism...")
                write_determinism(f'{output_dir}{determinism_file}', callback)
            else:
                stdout_print(f"no callback generated")
                stdout_print(f"writing determinism...")
                write_determinism(f'{output_dir}{determinism_file}')
        else:
            stdout_print(f"invalid user input, enter {valid_input}")
    else:
        stdout_print("no user input found")

    stdout_print("DONE!")
