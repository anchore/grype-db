import os
import requests
import shutil

# the credentials are not required for localstack, but the boto3 client will complain if they are not set
os.environ["AWS_ACCESS_KEY_ID"] = "test"
os.environ["AWS_SECRET_ACCESS_KEY"] = "test"

from grype_db_manager import s3utils
from grype_db_manager.cli import config


def main():
    cfg = config.load(".grype-db-manager.yaml")

    s3_bucket = cfg.distribution.s3_bucket
    region = cfg.distribution.aws_region

    if not bucket_exists(s3_bucket):
        print(f"creating bucket {s3_bucket!r}")
        s3 = s3utils.ClientFactory.new()
        s3.create_bucket(Bucket=s3_bucket, CreateBucketConfiguration={"LocationConstraint": region})

    print("done!")


def bucket_exists(bucket: str):
    try:
        list(s3utils.get_matching_s3_objects(bucket=bucket, prefix=""))
        return True
    except Exception as e:
        pass
    return False


if __name__ == "__main__":
    main()
