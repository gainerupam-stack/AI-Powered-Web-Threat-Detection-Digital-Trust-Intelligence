// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Stores only a report digest; never store URLs or investigation content.
contract ReportRegistry {
    struct Record {
        address registrar;
        uint64 timestamp;
        bool exists;
    }

    mapping(bytes32 => Record) public records;
    event ReportRegistered(bytes32 indexed reportHash, address indexed registrar, uint64 timestamp);

    function registerReport(bytes32 reportHash) external {
        require(reportHash != bytes32(0), "Empty report hash");
        require(!records[reportHash].exists, "Already registered");
        uint64 ts = uint64(block.timestamp);
        records[reportHash] = Record(msg.sender, ts, true);
        emit ReportRegistered(reportHash, msg.sender, ts);
    }
}
