"""
Merkle tree for log-batch integrity (hardened version).

Fixes over the first version:
  * Domain separation: leaves are hashed with a 0x00 prefix and inner nodes
    with a 0x01 prefix, so an inner node can never be passed off as a leaf.
  * No duplicate-leaf ambiguity: an unpaired node is promoted to the next
    level unchanged instead of being hashed with a copy of itself, so
    [a, b, c] and [a, b, c, c] now have DIFFERENT roots.
  * Canonical JSON rejects NaN/Infinity (they have no stable encoding).
"""

import hashlib
import json
from typing import List, Sequence, Tuple

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

Proof = List[Tuple[str, str]]  # [("left"|"right", sibling_hash_hex), ...]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(entry: dict) -> bytes:
    """Stable byte encoding: sorted keys, no whitespace, no NaN/Infinity."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def hash_leaf(entry: dict) -> str:
    return _sha256_hex(LEAF_PREFIX + canonical_json(entry))


def hash_pair(left_hex: str, right_hex: str) -> str:
    return _sha256_hex(NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


class MerkleTree:
    def __init__(self, log_entries: Sequence[dict]):
        if not log_entries:
            raise ValueError("Cannot build a Merkle tree from an empty batch")
        self.leaves: List[str] = [hash_leaf(e) for e in log_entries]
        self.levels: List[List[str]] = self._build_levels(self.leaves)

    @staticmethod
    def _build_levels(leaves: List[str]) -> List[List[str]]:
        levels = [leaves]
        current = leaves
        while len(current) > 1:
            nxt = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    nxt.append(hash_pair(current[i], current[i + 1]))
                else:
                    nxt.append(current[i])  # unpaired node is promoted unchanged
            levels.append(nxt)
            current = nxt
        return levels

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def get_proof(self, index: int) -> Proof:
        if index < 0 or index >= len(self.leaves):
            raise IndexError("log index out of range for this batch")
        proof: Proof = []
        idx = index
        for level in self.levels[:-1]:
            if idx % 2 == 1:
                proof.append(("left", level[idx - 1]))
            elif idx + 1 < len(level):
                proof.append(("right", level[idx + 1]))
            # else: promoted node, no sibling at this level
            idx //= 2
        return proof


def verify_proof(leaf_hash: str, proof: Sequence[Sequence[str]], expected_root: str) -> bool:
    """Recompute the root from a leaf and its proof path; True only on exact match."""
    try:
        current = leaf_hash
        for side, sibling in proof:
            if side == "left":
                current = hash_pair(sibling, current)
            elif side == "right":
                current = hash_pair(current, sibling)
            else:
                return False
        return current == expected_root
    except ValueError:
        return False
