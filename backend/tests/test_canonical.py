from app.canonical import report_sha256, canonical_json

def test_key_order_does_not_change_hash():
    assert report_sha256({"b": 2, "a": 1}) == report_sha256({"a": 1, "b": 2})

def test_hash_is_sha256_hex():
    assert len(report_sha256({"x": 1})) == 64
