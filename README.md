# iExecCoinbaseOracle
## on-chain Bitcoin price feed using iExec TEE workerpool, encryped API key, and Coinbase price oracle API

#####################################################  
MREnclave:ef741ecfb00b6525c41c711d2d176805f7389a119a8beab8796cf47387bc9980|348220620c36778d3d3ef493638042d8|16e7c11e75448e31c94d023e40ece7429fb17481bc62f521c8f70da9c48110a1  
#####################################################

**iExec dapp**

written in python and ran within a docker image by an iExec TEE workerpool  
calls coinbase oracle API for current BTC or ETH price  
workerpool returns callback message on-chain of price and signature  
signature verifies coinbase signed the message with their private key  
coinbase API key is encrypted and secured by Intel SGX and SCONE  


**smart contract**

task id of dapp result is returned via event after successful run  
user/bot triggers  smart contract with the task id  
smart contract retrieves task result bytes on-chain  
smart contract processes data (message and signature of btc price) from task  
verifies message was signed by coinbase on-chain within the smart contract  
verifies that price is newer than latest price by comparing timestamps  
smart contract writes/updates latest price on-chain along with timestamp  
smart contract returns current BTC or ETH price and timestamp from the signed coinbase message  
contract functions based on Open Oracle format  


**iExec price feed using Coinbase Price Oracle Demo v1**


https://gateway.pinata.cloud/ipfs/QmVGVy54T5XDg4tH2iZUpmnKoxNyoUaZUriNwZKGUNnFpD/

connects to doracle smart contract using a web3 wallet such as metamask or infura.io node  
uses web3.js to query smart contract  
all events in certain block range returned  
reading the ethereum logs for events is faster than directly reading from smart contract  
an array of price entries based on event data is created  
d3.js is used to draw interactive chart and table displaying price  


**TO-DO**

clean up js/html/css  
add Open Oracle mainnet connectivity via a daemon  
since prices are signed no trust is lost  
rewrite readme  
