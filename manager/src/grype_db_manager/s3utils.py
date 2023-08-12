import logging

import boto3  # type: ignore


class ClientFactory:
    endpoint_url = None
    region = None
    
    @classmethod
    def set_endpoint_url(cls, endpoint_url):
        cls.endpoint_url = endpoint_url

    @classmethod
    def set_region_name(cls, region):
        cls.region = region

    @classmethod
    def new(cls):
        kwargs = {}
        if cls.endpoint_url:
            kwargs["endpoint_url"] = cls.endpoint_url

        if cls.region:
            kwargs["region_name"] = cls.region

        return boto3.client("s3", **kwargs)
    

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


def download_to_file(bucket: str, key: str, path: str, client_factory=ClientFactory):
    logging.debug(f"downloading file from s3 bucket={bucket} key={key} to local={path}")

    s3 = client_factory.new()

    # boto is a little too verbose... let's tone that down just for a bit
    with LoggingContext(level=logging.WARNING):
        s3.download_file(Bucket=bucket, Key=key.lstrip("/"), Filename=path)


def upload(bucket: str, key: str, contents: str, client_factory=ClientFactory, **kwargs):
    logging.debug(f"uploading to s3 bucket={bucket} key={key}")

    # boto is a little too verbose... let's tone that down just for a bit
    with LoggingContext(level=logging.WARNING):
        s3 = client_factory.new()
        s3.put_object(Body=contents, Bucket=bucket, Key=key.lstrip("/"), **kwargs)


def upload_file(bucket: str, key: str, path: str, client_factory=ClientFactory, **kwargs):
    logging.debug(f"uploading file={path} to s3 bucket={bucket} key={key}")

    # boto is a little too verbose... let's tone that down just for a bit
    with LoggingContext(level=logging.WARNING):
        s3 = client_factory.new()
        s3.upload_file(path, bucket, key.lstrip("/"))


def get_s3_object_contents(bucket: str, key: str, client_factory=ClientFactory):
    logging.debug(f"get s3 contents bucket={bucket} key={key}")

    # boto is a little too verbose... let's tone that down just for a bit
    with LoggingContext(level=logging.WARNING):
        s3 = client_factory.new()
        try:
            obj = s3.get_object(Bucket=bucket, Key=key)
            return obj["Body"].read().decode("utf-8")
        except s3.exceptions.NoSuchKey:
            return


def get_matching_s3_objects(bucket: str, prefix: str = "", suffix: str = "", client_factory=ClientFactory):
    s3 = client_factory.new()
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
