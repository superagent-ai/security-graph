#!/usr/bin/env python3
"""Explicit operator setup. Inference itself never accesses Hugging Face."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
from huggingface_hub import snapshot_download

REVISION = "a85b127321d580d65176c89ced8273f305745d85"
WEIGHTS_SHA256 = "df853bf7fe424420011f3d0c47a05d7341aa9eefa7fb9f203ea4aada4ad95b72"
parser = argparse.ArgumentParser()
parser.add_argument("--model-dir", required=True)
args = parser.parse_args()
path = Path(args.model_dir).resolve()
snapshot_download("SupersonicLabs/Julia-1", revision=REVISION, local_dir=path)
with (path / "model.safetensors").open("rb") as weights:
    if hashlib.file_digest(weights, "sha256").hexdigest() != WEIGHTS_SHA256:
        raise ValueError("downloaded model weights mismatch")
subprocess.run([sys.executable, "-m", "pip", "install", "-e", str(path)], check=True)
(path / "security-graph-revision").write_text(REVISION + "\n")
print("Installed pinned Julia-1 checkpoint and runtime")
