#!/usr/bin/env python3
import yaml
import sys
import subprocess

with open(".grype-db.yaml") as f:
    providers = [x["name"] for x in yaml.safe_load(f.read()).get("provider", {}).get("configs", [])]

print(f"providers: {providers}")
for provider in providers:
    subprocess.run(f"make download-provider-cache provider={provider}", shell=True, check=True, stdout=sys.stdout, stderr=sys.stderr)
