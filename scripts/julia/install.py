#!/usr/bin/env python3
"""Prepare a verified runtime/data bundle without executing remote build code."""
import argparse
import os
from pathlib import Path
import shutil
import tempfile

from bundle import MANIFEST, REVISION, verify_bundle, verify_file


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--source-dir", help="Optional existing download; still hash-verified")
    args = parser.parse_args()
    target = Path(args.model_dir).absolute()
    if target.exists() or target.is_symlink():
        raise ValueError("model directory must not exist; prepare a new bundle")
    with tempfile.TemporaryDirectory(prefix="julia-setup-", dir=target.parent) as temp:
        temp = Path(temp)
        if args.source_dir:
            source = Path(args.source_dir)
        else:
            from huggingface_hub import snapshot_download
            source = Path(snapshot_download(
                MANIFEST["repository"], revision=REVISION,
                allow_patterns=list(MANIFEST["files"]), local_dir=temp / "download",
            ))
        # Verify every selected code/config/weight file, not just the checkpoint.
        for name in MANIFEST["files"]:
            verify_file(source, name)
        prepared = temp / "bundle"
        prepared.mkdir()
        for name in MANIFEST["files"]:
            destination = prepared / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, destination)
        (prepared / "security-graph-revision").write_text(REVISION + "\n")
        verify_bundle(prepared)
        os.rename(prepared, target)
    print("Prepared verified Julia-1 runtime and data; no model package was built")


if __name__ == "__main__":
    main()
