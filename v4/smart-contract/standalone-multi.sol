pragma solidity ^0.6.6;

contract CoinBaseDOracle
{
	event Update(string key, uint64 timestamp, uint64 value);

	struct Datum {
	uint64 timestamp;
	uint64 value;
	}

	mapping(string => Datum) private data;

	//hardcode public address for security
	address public constant coinbaseAddress = 0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC;
    
	// follows OpenOraclePriceData.sol
	function processResult(bytes memory _result) public {
		// decode results
		(bytes memory message, bytes memory signature) = abi.decode(_result, (bytes, bytes));

		// verify signature
		(bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
		bytes32 hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(message)));
		require(ecrecover(hash, v, r, s) == coinbaseAddress, "invalid signature");

		// get data in message (kind always "prices")
		(string memory kind, uint64 timestamp, string memory key, uint64 value) = abi.decode(message, (string, uint64, string, uint64));

		// get current stored value
		Datum storage prior = data[key];

		// check if timestamp is newer
		require(timestamp > prior.timestamp, "old timestamp");
		data[key] = Datum(timestamp, value);
		emit Update(key, timestamp, value);

	}

	function get(string calldata key) external view returns (uint64, uint64) {
		Datum storage datum = data[key];
		return (datum.timestamp, datum.value);
	}
    
    	function getPrice(string calldata key) external view returns (uint64) {
        	return data[key].value;
	}
    
     	function getTimestamp(string calldata key) external view returns (uint64) {
        	return data[key].timestamp;
	}
}
