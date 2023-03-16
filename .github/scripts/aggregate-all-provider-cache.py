#!/usr/bin/env python3
import os
import ast
import sys
import subprocess

output = os.environ.get("PROVIDERS_USED", None)

if not output:
    print(f"invoking grype-db to get list of providers to use")
    output = subprocess.run("make show-providers", shell=True, check=True, stdout=subprocess.PIPE, stderr=sys.stderr).stdout
else:
    print("using values from $PROVIDERS_USED environment variable")

print(f"output:   {output!r}")

# why in the world would we use ast instead of JSON?!
# short answer: python borks when there are strings with single quotes instead of double quotes
providers = ast.literal_eval(output)

print(f"providers: {providers}")

for provider in providers:
    subprocess.run(f"make download-provider-cache provider={provider}", shell=True, check=True, stdout=sys.stdout, stderr=sys.stderr)
