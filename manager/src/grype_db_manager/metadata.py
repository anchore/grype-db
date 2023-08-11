import tarfile
import tempfile
import json
from pathlib import Path
from dataclasses import dataclass

import zstandard
from dataclass_wizard import fromdict, asdict

FILE = "metadata.json"


@dataclass
class Metadata:
    built: str
    version: int
    # note: the checksum is not included here since that is for the contained db file, not the checksum of the archive itself

    @classmethod
    def from_json(cls, contents: str):
        return cls.from_dict(json.loads(contents))

    @classmethod
    def from_dict(cls, contents: dict):
        return fromdict(cls, contents)

    def to_json(self, indent=None):
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_dict(self):
        return asdict(self)


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
