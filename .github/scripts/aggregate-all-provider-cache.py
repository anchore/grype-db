#!/usr/bin/env python3
import json
import sys
import subprocess

output = subprocess.run("make show-providers", shell=True, check=True, stdout=subprocess.PIPE, stderr=sys.stderr).stdout
providers = json.loads(output)

print(f"providers: {providers}")
for provider in providers:
    subprocess.run(f"make download-provider-cache provider={provider}", shell=True, check=True, stdout=sys.stdout, stderr=sys.stderr)
