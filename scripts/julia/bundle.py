"""Validate the exact runtime/data tree before importing any model code."""
import hashlib
import json
from pathlib import Path

MANIFEST = json.loads(Path(__file__).with_name("manifest.json").read_text())
REVISION = MANIFEST["revision"]


def verify_file(root, name):
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or linked model file")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != MANIFEST["files"][name]:
            raise ValueError("model bundle integrity mismatch")


def verify_bundle(root):
    if root.is_symlink():
        raise ValueError("linked model directory")
    allowed = set(MANIFEST["files"]) | {"security-graph-revision"}
    for path in root.rglob("*"):
        if path.is_symlink() or (path.is_file() and path.relative_to(root).as_posix() not in allowed):
            raise ValueError("unexpected model bundle file")
    for name in MANIFEST["files"]:
        verify_file(root, name)
    if (root / "security-graph-revision").read_text().strip() != REVISION:
        raise ValueError("model revision mismatch")
