import logging

import boto3  # type: ignore


class LoggingContext(object):
    def __init__(self, logger=None, level=None):
        self.logger = logger or logging.root
        self.level = level

    def __enter__(self):
        if self.level is not None:
            self.old_level = self.logger.level
            self.logger.setLevel(self.level)

    def __exit__(self, et, ev, tb):
        if self.level is not None:
            self.logger.setLevel(self.old_level)

def download_to_file(bucket: str, key: str, path: str):
    logging.info(f"downloading file from s3 bucket={bucket} key={key} to local={path}")

    s3 = boto3.client("s3")
    og_level = logging.root.level

    # boto is a little too verbose... let's tone that down just for a bit
    with LoggingContext(level=logging.WARNING):
        s3.download_file(Bucket=bucket, Key=key.lstrip("/"), Filename=path)


def upload(bucket: str, key: str, contents: str, **kwargs):
    logging.info(f"uploading to s3 bucket={bucket} key={key}")

    # boto is a little too verbose... let's tone that down just for a bit
    with LoggingContext(level=logging.WARNING):
        s3 = boto3.client("s3")
        s3.put_object(Body=contents, Bucket=bucket, Key=key.lstrip("/"), **kwargs)


def get_s3_object_contents(bucket: str, key: str):
    logging.info(f"get s3 contents bucket={bucket} key={key}")

    # boto is a little too verbose... let's tone that down just for a bit
    with LoggingContext(level=logging.WARNING):
        s3 = boto3.client("s3")
        try:
            obj = s3.get_object(Bucket=bucket, Key=key)
            return obj["Body"].read().decode("utf-8")
        except s3.exceptions.NoSuchKey:
            return


def get_matching_s3_objects(bucket: str, prefix: str = "", suffix: str = ""):
    s3 = boto3.client("s3")
    paginator = s3.get_paginator("list_objects_v2")

    kwargs = {"Bucket": bucket}

    # we can pass the prefix directly to the S3 API.  If the user has passed
    # a tuple or list of prefixes, we go through them one by one.
    if isinstance(prefix, str):
        prefixes = (prefix,)
    else:
        prefixes = prefix

    for key_prefix in prefixes:
        kwargs["Prefix"] = key_prefix.lstrip("/")

        for page in paginator.paginate(**kwargs):
            try:
                contents = page["Contents"]
            except KeyError:
                break

            for obj in contents:
                if obj["Key"].endswith(suffix):
                    yield obj


def get_matching_s3_keys(bucket: str, prefix: str = "", suffix: str = ""):
    for obj in get_matching_s3_objects(bucket, prefix, suffix):
        yield obj["Key"]
