// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * LogAnchor — stores one Merkle root per sealed log batch.
 *
 * The important property is WRITE-ONCE: after a root is anchored for a
 * batch, nobody (including the owner) can overwrite it. That is what
 * makes the on-chain copy a trustworthy reference to compare against.
 */
contract LogAnchor {
    address public owner;
    uint256 public lastBatchId;

    mapping(uint256 => bytes32) private roots;
    mapping(uint256 => uint256) private anchoredAt;

    event RootAnchored(uint256 indexed batchId, bytes32 merkleRoot, uint256 timestamp);

    constructor() {
        owner = msg.sender;
    }

    function anchorRoot(uint256 batchId, bytes32 merkleRoot) external {
        require(msg.sender == owner, "only owner can anchor");
        require(merkleRoot != bytes32(0), "empty root");
        require(roots[batchId] == bytes32(0), "batch already anchored");

        roots[batchId] = merkleRoot;
        anchoredAt[batchId] = block.timestamp;
        if (batchId > lastBatchId) {
            lastBatchId = batchId;
        }
        emit RootAnchored(batchId, merkleRoot, block.timestamp);
    }

    function getRoot(uint256 batchId) external view returns (bytes32 root, uint256 timestamp) {
        return (roots[batchId], anchoredAt[batchId]);
    }
}
