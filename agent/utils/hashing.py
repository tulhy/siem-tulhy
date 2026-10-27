import hashlib
from functools import lru_cache
from pathlib import Path

@lru_cache(maxsize=1024)
def _hash(path, size, modified):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(131072), b''):
            digest.update(chunk)
    return digest.hexdigest()

def executable_hash(path, max_bytes):
    if not path:
        return None
    try:
        info = Path(path).stat()
        if info.st_size > max_bytes:
            return None
        return _hash(path, info.st_size, info.st_mtime_ns)
    except (OSError, PermissionError):
        return None
