#!/usr/bin/env bash
set -e # fail immediately if any command fails

timing_file="$(dirname $0)/curl-timing-info-template.txt"

test_download() {
  url=$1

  # download with IPv6 -- unsupported in Github actions for now
  # curl -sL6 -w "@$timing_file" -D /dev/stdout --max-time 30 $url -o /dev/null

  # download with IPv4
  curl -sL4 -w "@$timing_file" -D /dev/stdout --max-time 120 $url -o /dev/null
}

test_download https://toolbox-data.anchore.io/grype/databases/listing.json

# get the latest db file
db_file="$(curl -sL https://toolbox-data.anchore.io/grype/databases/listing.json | jq -r '.["available"]["5"][0]["url"]')"

test_download $db_file
