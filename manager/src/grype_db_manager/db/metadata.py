import json
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

import zstandard
from dataclass_wizard import asdict, fromdict

FILE = "metadata.json"


@dataclass
class Metadata:
    built: str
    version: int
    # note: the checksum is not included here since that is for the contained db file, not the archive

    @classmethod
    def from_json(cls, contents: str) -> "Metadata":
        return cls.from_dict(json.loads(contents))

    @classmethod
    def from_dict(cls, contents: dict) -> "Metadata":
        return fromdict(cls, contents)

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_dict(self) -> dict:
        return asdict(self)


def from_archive(path: str) -> Metadata:
    if path.endswith(".tar.gz"):
        return from_tar_gz(path)
    if path.endswith(".tar.zst"):
        return from_tar_zst(path)
    msg = f"unsupported archive type: {path}"
    raise RuntimeError(msg)


def from_tar(tar_obj: tarfile.TarFile) -> Metadata:
    f = tar_obj.extractfile(tar_obj.getmember(FILE))
    if not f:
        msg = f"failed to find {FILE}"
        raise RuntimeError(msg)
    return Metadata.from_json(f.read().decode())


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
