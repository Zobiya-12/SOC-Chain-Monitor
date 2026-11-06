import pytest

from app.merkle import MerkleTree, canonical_json, hash_leaf, hash_pair, verify_proof


def logs(n):
    return [{"k": str(i)} for i in range(n)]


@pytest.mark.parametrize("n", range(1, 14))
def test_every_proof_verifies(n):
    tree = MerkleTree(logs(n))
    for i in range(n):
        assert verify_proof(tree.leaves[i], tree.get_proof(i), tree.root)


def test_changing_any_log_changes_the_root():
    base = MerkleTree(logs(5)).root
    changed = logs(5)
    changed[3]["k"] = "evil"
    assert MerkleTree(changed).root != base


def test_duplicate_leaf_ambiguity_is_fixed():
    a, b, c = {"k": "a"}, {"k": "b"}, {"k": "c"}
    assert MerkleTree([a, b, c]).root != MerkleTree([a, b, c, c]).root
    five, six = logs(5), logs(5) + [logs(5)[-1]]
    assert MerkleTree(five).root != MerkleTree(six).root


def test_leaf_and_node_hashes_are_domain_separated():
    left, right = hash_leaf({"k": "1"}), hash_leaf({"k": "2"})
    # An inner node hashed as if it were a leaf must not equal the real inner node.
    assert hash_pair(left, right) != hash_leaf({"k": left + right})


def test_wrong_proof_or_root_fails():
    tree = MerkleTree(logs(6))
    proof = tree.get_proof(2)
    assert not verify_proof(tree.leaves[3], proof, tree.root)
    assert not verify_proof(tree.leaves[2], proof, "00" * 32)
    assert not verify_proof(tree.leaves[2], [("sideways", "00" * 32)], tree.root)
    assert not verify_proof(tree.leaves[2], [("left", "not-hex")], tree.root)


def test_key_order_does_not_matter():
    assert hash_leaf({"a": 1, "b": 2}) == hash_leaf({"b": 2, "a": 1})


def test_nan_is_rejected():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_empty_batch_and_bad_index():
    with pytest.raises(ValueError):
        MerkleTree([])
    with pytest.raises(IndexError):
        MerkleTree(logs(3)).get_proof(3)
