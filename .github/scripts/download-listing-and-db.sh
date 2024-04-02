#!/usr/bin/env bash
set -x

timing_file="$(dirname $0)/curl-timing-info-template.txt"

test_download() {
  url=$1

  # download with IPv6
  curl -vsL6 -w "@$timing_file" $url -o /dev/null

  # download with IPv4
  curl -vsL4 -w "@$timing_file" $url -o /dev/null
}

test_download https://toolbox-data.anchore.io/grype/databases/listing.json

# get the latest db file
db_file="$(curl -sL https://toolbox-data.anchore.io/grype/databases/listing.json | jq -r '.["available"]["5"][0]["url"]')"

test_download $db_file
