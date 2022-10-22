import urllib.request, json
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

URL = "https://blockchain-solveme-badb63f36729ee3a.2022.ductf.dev"


# read the ABI
with open("SolveMe_sol_SolveMe.abi", "r") as file:
    abi = json.load(file)

# read from the challenge URL
with urllib.request.urlopen(URL + "/challenge") as url:
    data = json.load(url)
    
    address = data["contract_address"][0]["address"]
    wallet = data["player_wallet"]["address"]
    private_key = data["player_wallet"]["private_key"]

web3 = Web3(HTTPProvider(URL))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)


contract = web3.eth.contract(address=address, abi=abi)

nonce = web3.eth.getTransactionCount(wallet)

gas_price = web3.eth.gas_price
gas_limit = 1000

# builds the transaction to call solveChallenge function
tx = contract.functions.solveChallenge().buildTransaction(
    {
        "nonce": nonce,
        "from": wallet,
        "gas": gas_limit,
        "gasPrice": gas_price
    }
)

# sign it
signed_tx = web3.eth.account.sign_transaction(tx, private_key)

# send it
tx_hash = web3.toHex(web3.eth.sendRawTransaction(signed_tx.rawTransaction))
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

print(tx_receipt["status"])
