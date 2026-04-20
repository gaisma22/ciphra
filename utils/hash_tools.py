# hash_tools.py
# File hashing utility.
# compute_hash: returns hex digest for a given file path and algorithm.

import hashlib
import os

_SUPPORTED = {"md5", "sha1", "sha256", "sha512"}

# Returns hex digest for the file at fp using the given algorithm
def compute_hash(fp, algo="sha256", chunk_size=1048576):
    if not os.path.exists(fp):
        raise FileNotFoundError(f"File not found: {fp}")
    if os.path.getsize(fp) == 0:
        raise ValueError(f"File is empty: {fp}")
    if algo not in _SUPPORTED:
        raise ValueError(
            f"Unsupported algorithm: {algo}. Use one of: md5, sha1, sha256, sha512"
        )
    h = hashlib.new(algo)
    with open(fp, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()
