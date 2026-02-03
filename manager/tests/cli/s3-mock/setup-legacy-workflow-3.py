import os
import requests
import shutil

# the credentials are not required for localstack, but the boto3 client will complain if they are not set
os.environ["AWS_ACCESS_KEY_ID"] = "test"
os.environ["AWS_SECRET_ACCESS_KEY"] = "test"

from grype_db_manager import db, s3utils
from grype_db_manager.cli import config


def main():
    cfg = config.load(".grype-db-manager.yaml")

    s3_bucket = cfg.distribution.s3_bucket
    s3_path = cfg.distribution.s3_path
    region = cfg.distribution.aws_region

    # prep the listing cache dir
    listing_cache_dir = ".listing-cache"
    localstack_s3_endpoint = "localhost:4566"

    if not cache_exists(listing_cache_dir):
        download_cache(listing_cache_dir, localstack_s3_endpoint, s3_bucket, s3_path)

    if is_cache_prepped(listing_cache_dir, s3_bucket, s3_path):
        print("cache already prepped")
    else:
        prep_localstack(listing_cache_dir, s3_bucket, s3_path, region)
    show_localstack(s3_bucket)
    print("done!")


def download_cache(cache_dir: str, localstack_s3_endpoint: str, s3_bucket: str, s3_path: str):
    print("downloading cache")
    os.makedirs(cache_dir, exist_ok=True)

    # get the current listing file from s3
    oss_listing_url = "https://toolbox-data.anchore.io/grype/databases/listing.json"
    resp = requests.get(oss_listing_url)
    resp.raise_for_status()
    the_listing = db.Listing.from_json(resp.text)

    # download the latest db for each schema in the_listing.available
    downloaded = {}
    og_entries = {}
    for schema_version in the_listing.available.keys():
        entry = the_listing.available[schema_version][0]
        listing_cache_path = f"{cache_dir}/{entry.basename()}"
        print("downloading", entry.basename(), "to", cache_dir)

        with requests.get(entry.url, stream=True) as r:
            r.raise_for_status()
            with open(listing_cache_path, "wb") as f:
                shutil.copyfileobj(r.raw, f)

        downloaded[schema_version] = listing_cache_path
        og_entries[schema_version] = entry

    # craft a new listing file
    new_listing = db.listing.empty_listing()
    for schema_version in downloaded.keys():
        entry = og_entries[schema_version]

        # entry.url = f"http://{s3_bucket}.{localstack_s3_endpoint}/{s3_bucket}/{s3_path}/{entry.basename()}"
        entry.url = f"http://{localstack_s3_endpoint}/{s3_bucket}/{s3_path}/{entry.basename()}"

        new_listing.add(entry)

    new_listing_contents = new_listing.to_json()

    # write out to the listing file
    local_listing_path = f"{cache_dir}/listing.json"
    with open(local_listing_path, "w") as f:
        f.write(new_listing_contents)


def prep_localstack(cache_dir: str, s3_bucket: str, s3_path: str, region: str):
    print("prepping localstack")

    if not bucket_exists(s3_bucket):
        s3 = s3utils.ClientFactory.new()
        s3.create_bucket(Bucket=s3_bucket, CreateBucketConfiguration={"LocationConstraint": region})

    # load the listing file from the cache dir
    local_listing_path = f"{cache_dir}/listing.json"
    with open(local_listing_path, "r") as f:
        the_listing = db.Listing.from_json(f.read())

    for schema_version, entries in the_listing.available.items():
        print("processing schema", schema_version)
        for entry in entries:
            local_db_path = f"{cache_dir}/{entry.basename()}"

            print("uploading DB", entry.basename(), "to", s3_bucket, s3_path)
            s3utils.upload_file(s3_bucket, f"{s3_path}/{entry.basename()}", local_db_path)

    print("uploading listing to", s3_bucket, s3_path)
    s3utils.upload_file(s3_bucket, f"{s3_path}/listing.json", local_listing_path)


def show_localstack(bucket: str, path: str = ""):
    print("bucket", bucket, "contents:")
    for obj in s3utils.get_matching_s3_objects(bucket=bucket, prefix=path):
        print("   ", obj["Key"])


def cache_exists(cache_dir: str):
    listing_path = f"{cache_dir}/listing.json"
    return os.path.exists(listing_path)


def is_cache_prepped(cache_dir: str, s3_bucket: str, s3_path: str):
    local_listing_path = f"{cache_dir}/listing.json"
    with open(local_listing_path, "r") as f:
        the_listing = db.Listing.from_json(f.read())

    # check that each entry in the listing has a corresponding object in s3
    paths = [f"{s3_path}/listing.json"]
    for schema_version, entries in the_listing.available.items():
        for entry in entries:
            expected_path = f"{s3_path}/{entry.basename()}"
            paths.append(expected_path)

    found = []
    try:
        s3_listing = list(s3utils.get_matching_s3_objects(bucket=s3_bucket, prefix=""))
    except Exception:
        return False

    for obj in s3_listing:
        found.append(obj["Key"])

    if set(found) != set(paths):
        return False
    return True


def bucket_exists(bucket: str):
    try:
        list(s3utils.get_matching_s3_objects(bucket=bucket, prefix=""))
        return True
    except Exception as e:
        pass
    return False


if __name__ == "__main__":
    main()
