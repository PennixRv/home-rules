import gzip
import hashlib
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.request import urlopen


VERSION = "v1.19.18"
ASSET = f"mihomo-linux-amd64-v1-{VERSION}.gz"
URL = f"https://github.com/MetaCubeX/mihomo/releases/download/{VERSION}/{ASSET}"
ARCHIVE_SHA256 = "4b7f2a8cd5c772153ec975f0cee74efbc8f294d6d3e64623b079674d8a903b49"
BINARY_SHA256 = "8ae1d3853544408f346775d409dadf12aef3fd86ac522a5cf344b22e1b6a3164"


def mihomo_binary():
    cache = Path(os.environ.get("MIHOMO_CACHE", "/data/state/.tools"))
    binary = cache / ASSET.removesuffix(".gz")
    if binary.is_file() and os.access(binary, os.X_OK):
        with binary.open("rb") as existing:
            if hashlib.file_digest(existing, "sha256").hexdigest() == BINARY_SHA256:
                return binary
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    with urlopen(URL, timeout=45) as response:
        archive = response.read((32 << 20) + 1)
    if hashlib.sha256(archive).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("Mihomo archive failed the upstream checksum")
    data = gzip.decompress(archive)
    if hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError("Mihomo executable failed the checksum")
    with NamedTemporaryFile(dir=cache, delete=False) as temporary:
        pending = Path(temporary.name)
        try:
            temporary.write(data)
            temporary.close()
            pending.chmod(0o700)
            pending.replace(binary)
        finally:
            pending.unlink(missing_ok=True)
    return binary
