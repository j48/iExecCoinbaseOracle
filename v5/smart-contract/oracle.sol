// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@iexec/solidity/contracts/ERC1154/IERC1154.sol";
import "@iexec/solidity/contracts/ERC2362/IERC2362.sol";
import "@iexec/doracle/contracts/IexecDoracle.sol";

contract PriceOracle is IexecDoracle, Ownable, IOracleConsumer, IERC2362
{
	event Update(bytes32 indexed oracleCallID, string indexed key, uint64 timestamp, uint64 value);

	struct Datum {
		bytes32 oracleCallID;
        uint64 date;
        uint64 value;
    }

    mapping(bytes32 => Datum) private values;

    address public constant coinbaseAddress = 0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC;

	constructor()
	public IexecDoracle(address(0))
	{}

	function updateEnv(
	  address _authorizedApp
	, address _authorizedDataset
	, address _authorizedWorkerpool
	, bytes32 _requiredtag
	, uint256 _requiredtrust
	)
	public onlyOwner
	{
		_iexecDoracleUpdateSettings(_authorizedApp, _authorizedDataset, _authorizedWorkerpool, _requiredtag, _requiredtrust);
	}

	// ERC1154 - Callback processing
	function receiveResult(bytes32 _callID, bytes calldata)
	external override
	{
		// Decode results
		(bytes memory message, bytes memory signature) = abi.decode(_iexecDoracleGetVerifiedResult(_callID), (bytes, bytes));

		// Decode message
        (string memory kind, uint64 timestamp, string memory key, uint64 value) = abi.decode(message, (string, uint64, string, uint64));

        // Error handling
        require(keccak256(abi.encodePacked(kind)) == keccak256(abi.encodePacked("prices")), "Kind of data must be 'prices'");

        // Verify signature
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(_signature, (bytes32, bytes32, uint8));
        bytes32 hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(message)));
        require(ecrecover(hash, v, r, s) == coinbaseAddress, "Invalid signature");

        // Convert key to id
        bytes32 id = keccak256(bytes(key));

		// Current stored value
        Datum storage prior = values[id];

        // Check timestamp
        require(timestamp > prior.date, "Old timestamp");
        values[id] = Datum(_callID, timestamp, value);

        emit Update(_callID, key, timestamp, value);

	}

	// ERC2362 - ADO result viewer
	function valueFor(bytes32 _id)
	external override view returns (int256, uint256, uint256)
	{
		if (values[_id].oracleCallID == bytes32(0))
		{
			return (0, 0, 404);
		}
		else
		{
			return (values[_id].value, values[_id].date, 200);
		}
	}

	// Functions using string input (using OpenOracle functions)
	function get(string calldata key) external view returns (uint64, uint64) {
        Datum storage datum = values[keccak256(bytes(key))];
        return (datum.date, datum.value);
    }
    
    function getPrice(string calldata key) external view returns (uint64) {
        return values[keccak256(bytes(key))].value;
    }
    
     function getTimestamp(string calldata key) external view returns (uint64) {
        return values[keccak256(bytes(key))].date;
    }

}