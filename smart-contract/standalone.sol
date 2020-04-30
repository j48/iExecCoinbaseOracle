pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

contract CoinBaseDoracle
{
  // data that is sent in an event
  // basically cheap and fast storage that can be accessed by web3.js/dapps
  // can monitor a smartcontract and track all of its events if needed without using expensive SSTORE
  // can search by event name and/or filter by index fields (up to 3)
  // can not be accessed by smartcontracts
  // should add tx hash as the indexed field
  event NewPrice(uint256 row, uint256 price, uint256 timestamp);

  // define saved (on chain) variables and hardcoded values
  // undeclared get written to 0 after creation

  uint256 private totalRows;
  
  // this is the string in the message data
  // coinbase describes each price as a market "BTC-USD", "ETH-USD"
  // currently only coin name returned "BTC", "ETH"
  string public constant market = 'BTC';
  
  // sandbox address = 0xD9F775d8351C13aa02FDC39080947c79e454cb19
  // mainnet address = 0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC
  address public constant coinbaseAddress = 0xD9F775d8351C13aa02FDC39080947c79e454cb19;

  // mappings get set by a key (use struct for more than one saved value)
  mapping(uint256 => uint256) private prices;
  mapping(uint256 => uint256) private timestamps;

  // row/price/timestamp functions
  function latestPrice() external view returns (uint256)
  {
    return prices[totalRows];
  }

  function latestTimestamp() external view returns (uint256)
  {
    return timestamps[totalRows];
  }

  function getPrice(uint256 _rowId) external view returns (uint256)
  {
    return prices[_rowId];
  }

  function getTimestamp(uint256 _rowId) external view returns (uint256)
  {
    return timestamps[_rowId];
  }

  function latestRow() external view returns (uint256) {
    return totalRows;
  }

  // safe math - prevents overflows
  function safeAdd(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
      }

    // compare 2 strings
    function compareStrings(string memory a, string memory b) internal pure returns (bool) {
      return (keccak256(abi.encodePacked((a))) == keccak256(abi.encodePacked((b))) );
       }

    // decodes workerpool results into usable data
	function decodeResults(bytes memory results) internal pure returns(bytes memory, bytes memory)
	{ return abi.decode(results, (bytes, bytes)); }

	// decodes message into usable data
	function decodeMessage(bytes memory results) internal pure returns(string memory, uint256, string memory, uint256)
	{ return abi.decode(results, (string, uint256, string, uint256)); }

	// compares coinbase private key to message and signature
	function coinbaseCheck(bytes memory message, bytes memory signature) internal pure returns (bool) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        bytes32 hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(message)));

        return ecrecover(hash, v, r, s) == coinbaseAddress;
    }

	// ********************
	// *****START HERE*****
	// ********************
	// main function triggered by user/bot
	// _oracleCallID is the _taskid returned by workerpool (along with _results)
	// _results = callback from dapp (bytes message and bytes signature)
	// contract uses _oracleCallID and retrieves _results onchain
	// for testing:
	// replace bytes32 _oracleCallID with the bytes _results manually
	// all iExec interactions are stripped in this doracle smart contract

	function processResult(bytes memory _result)
	public
	{
	    // what gets decoded from _results
		bytes memory message;
		bytes memory signature;

		// Parse results
		// will also need to decode/parse message/sig later
		(message, signature) = decodeResults(_result);

		// because code cost gas its best to code in stages and fail instead of all at once then fail
		// two things need to be done if result is usable
		// 1. check if message signature is valid
		// 2. check if timestamp in message is newer than currently stored timestamp
		// for failure and success
		// must determine which order of actions that will potentially cost the least gas
		// this can be decided later once gas is calculated via tests

		// decoded message
		string memory kind;  // 'prices'
		uint256 timestamp;  // 1587735000
		string memory coin; // 'BTC'
		uint256 price;  // 7187525000

		(kind, timestamp, coin, price) = decodeMessage(message);

		// check right coin
		// hardcode 'BTC' and check if equal
		require(compareStrings(coin, market), "price in message not BTC");
		
		// coinbase message check
		// will compare address used to sign message to confirmed coinbase public key
		// will auto exit with message if false
		// determine if coinbase address hardcoded vs changeable by owner
		require(coinbaseCheck(message, signature), "message not signed by coinbase");

		// row is what is used to access doracle data onchain, it is a key to unlock data
		// like autoincrement database
		// get current row then add 1 to it
		// null uint256 is default 0
		uint256 currentRow = totalRows;

		// check newer timestamp
		// use safe math to compare timestamps
		require(timestamps[currentRow] < timestamp, "timestamp of message is too old");

		// will TRUST coinbase on price
		// basis of signed price oracle APIs

		//define new row number
		uint256 newRow = safeAdd(currentRow, 1);

		// this triggers event
		emit NewPrice(newRow, price, timestamp);

		// this get what gets saved on-chain at the end of processResult function if successful
		totalRows = newRow;
		prices[newRow] = price;
		timestamps[newRow] = timestamp;
	}
}
