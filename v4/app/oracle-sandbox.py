import base64
import hashlib
import hmac
import sys
import time
import os
import requests
import web3._utils.abi as eth_abi
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.auto import w3

SANDBOX = True

COINBASE_API_KEY_SANDBOX = 'cf02bc29889369578c9f441286c64b50'
COINBASE_API_SECRET_SANDBOX = 'ud3kODtta01RaBjZEGmghRgVE12+IoXU1QzLObS6Gi/2vkNpLj2Fo4RFzP7Hhclefw/4vc6ccQWO8OjLkZK6mw=='
COINBASE_PASSPHRASE_SANDBOX = '52ma272rs1s'

# ***VIEW ONLY*** (key, secret, passphrase from encrypted dataset)
# https://developers.coinbase.com/api/v2?shell#api-key
COINBASE_API_KEY = ''
COINBASE_API_SECRET = ''
COINBASE_PASSPHRASE = ''

# https://docs.pro.coinbase.com/#recovering-signatory
COINBASE_ORACLE_PUBLIC_KEY = '0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC'
COINBASE_ORACLE_PUBLIC_KEY_SANDBOX = '0xD9F775d8351C13aa02FDC39080947c79e454cb19'


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


def main(coin):
    if not SANDBOX:
        api_url = 'https://api.pro.coinbase.com'
        api_key = COINBASE_API_KEY
        api_secret = COINBASE_API_SECRET
        api_passphrase = COINBASE_PASSPHRASE
        public_key = COINBASE_ORACLE_PUBLIC_KEY
    else:
        api_url = 'https://api-public.sandbox.pro.coinbase.com'
        api_key = COINBASE_API_KEY_SANDBOX
        api_secret = COINBASE_API_SECRET_SANDBOX
        api_passphrase = COINBASE_PASSPHRASE_SANDBOX
        public_key = COINBASE_ORACLE_PUBLIC_KEY_SANDBOX

    api_types = ['string', 'uint256', 'string', 'uint256']

    # currently API just returns BTC/ETH values in same call
    url = api_url + '/oracle'
    print(f"oracle API URL: {url}")

    coinbase_api = CoinbaseProAPI(url, api_key, api_secret, api_passphrase)

    r = coinbase_api.call()

    print(f"oracle response: {r.text}")

    if r.status_code == 200:
        message = None
        ecdsa_signature = None

        result = r.json()

        try:
            for i, entry in enumerate(result['prices']):
                print(f"Coin: {entry}")

                if entry.lower() == coin.lower():
                    print("*COIN FOUND*")
                    message = result['messages'][i]
                    ecdsa_signature = result['signatures'][i]
                    break

                else:
                    print("skipping...")

        except Exception as e:
            print(f"error: {e}")

        if message:
            print(f"message: {message}")
            print(f"ECDSA signature: {ecdsa_signature}")

            v, r, s = sig2vrs(ecdsa_signature)
            print(f"v: {v}")
            print(f"r: {Web3.toHex(r)}")
            print(f"s: {Web3.toHex(s)}")

            print(f"coinbase public key: {public_key}")

            signer = get_message_signer(message, [v, r, s])

            if signer.lower() == public_key.lower():
                print(f"*MESSAGE VERIFIED*")

                decoded_message = decode_message(api_types, message)
                print(f"decoded message: {decoded_message}")

                print(f"*CREATING CALLBACK FOR DORACLE SMARTCONTRACT*")
                return create_callback(message, ecdsa_signature)

            else:
                print(f"*MESSAGE FAILED VERIFICATION*")

    else:
        print(f"API error ({r.status_code})")


# user input "ETH" or "BTC"
if __name__ == "__main__":
    root = ''
    input_dir = f'{root}iexec_in/'
    output_dir = f'{root}iexec_out/'
    callback_file = 'callback.iexec'
    determinism_file = 'determinism.iexec'
    valid_input = ['BTC', 'ETH']
    callback = None

    try:
        if os.environ['TEE']:
            try:
                output_dir = f"{root}{os.environ['TEE_FOLDER']}/"
            except KeyError:
                output_dir = f"{root}scone/"
            print(f"using TEE!")
    except KeyError:
        pass

    user_input = sys.argv[1] if len(sys.argv) > 1 else None

    print(f"user input: {user_input}")

    if user_input:
        if user_input.upper() in valid_input:
            callback = main(user_input)
        else:
            print("invalid user input, enter 'BTC' or 'ETH'")
    else:
        print("no user input found")

    if callback:
        print(f"callback: {callback}")
        print(f"writing callback...")
        write_callback(callback, f'{output_dir}{callback_file}')

        print(f"writing determinism...")
        write_determinism(f'{output_dir}{determinism_file}', callback)
    else:
        print(f"no callback generated")
        print(f"writing determinism...")
        write_determinism(f'{output_dir}{determinism_file}')

    print("DONE!")
