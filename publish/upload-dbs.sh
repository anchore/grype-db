#!/usr/bin/env bash
set -e

# make certain we are in CI (see https://docs.github.com/en/actions/reference/environment-variables#default-environment-variables)
if test -z "${CI}"; then
    echo "This is only intended to run within CI, not in a local development workflow."
    exit 1
fi

set -u

AWS_BUCKET=$1
AWS_BUCKET_PATH=$2
# note: this is additionally set as a constant in utils/constants.py
STAGE_DIR=$(git rev-parse --show-toplevel)/publish/stage

docker run --rm \
		-i \
		-e AWS_DEFAULT_REGION=us-west-2 \
		-e AWS_ACCESS_KEY_ID \
		-e AWS_SECRET_ACCESS_KEY \
		-v "${STAGE_DIR}/:/stagemount" \
		amazon/aws-cli \
			s3 cp /stagemount/ "s3://${AWS_BUCKET}/${AWS_BUCKET_PATH}/" \
			--recursive \
			--exclude '*' \
			--include '*.tar.gz' \
			--include '*.tar.zst' \
			--cache-control 'public,max-age=31536000'
