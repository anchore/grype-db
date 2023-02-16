import tarfile
import tempfile
from pathlib import Path
from dataclasses import dataclass

import zstandard
from dataclasses_json import dataclass_json

FILE = "metadata.json"


@dataclass_json
@dataclass
class Metadata:
    built: str
    version: int
    # note: the checksum is not included here since that is for the contained db file, not the checksum of the archive itself


def from_archive(path: str) -> Metadata:
    if path.endswith(".tar.gz"):
        return from_tar_gz(path)
    elif path.endswith(".tar.zst"):
        return from_tar_zst(path)
    raise RuntimeError(f"unsupported archive type: {path}")

def from_tar(tar_obj) -> Metadata:
    f = tar_obj.extractfile(tar_obj.getmember(FILE))
    if not f:
        raise RuntimeError(f"failed to find {FILE}")
    return Metadata.from_json(f.read().decode())  # type: ignore


def from_tar_gz(path: str) -> Metadata:
    with tarfile.open(path, "r") as a:
        return from_tar(a)

def from_tar_zst(path: str) -> Metadata:
    archive = Path(path).expanduser()
    dctx = zstandard.ZstdDecompressor(max_window_size=2147483648)

    with tempfile.TemporaryFile(suffix=".tar") as ofh:
        with archive.open("rb") as ifh:
            dctx.copy_stream(ifh, ofh)
        ofh.seek(0)
        with tarfile.open(fileobj=ofh) as z:
            return from_tar(z)
