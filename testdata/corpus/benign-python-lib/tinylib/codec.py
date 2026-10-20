"""Encode and decode small tokens and fetch a status page."""
import base64
import hashlib
import json
import os
import zlib

import requests


def encode_token(payload):
    """Pack a dict into a URL-safe token."""
    raw = zlib.compress(json.dumps(payload, sort_keys=True).encode("utf-8"))
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_token(token):
    """Unpack a token made by encode_token. The result is data, never code."""
    raw = zlib.decompress(base64.urlsafe_b64decode(token.encode("ascii")))
    return json.loads(raw.decode("utf-8"))


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def fetch_status(base_url):
    cache_dir = os.environ.get("TINYLIB_CACHE", "/tmp")
    response = requests.get(base_url + "/status", timeout=10)
    response.raise_for_status()
    return {"cache": cache_dir, "status": response.json()}
