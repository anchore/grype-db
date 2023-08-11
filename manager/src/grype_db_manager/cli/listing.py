from __future__ import annotations

import logging

import click

from grype_db_manager.cli import config, error
from grype_db_manager import distribution
from grype_db_manager import db
from grype_db_manager.db.format import Format


@click.group(name="listing", help="manage the grype-db listing file")
@click.pass_obj
def group(_: config.Application):
    pass


@group.command(name="create", help="create a new listing file based on the current S3 state")
@click.option("--ignore-missing-listing", "-i", default=False, help="ignore missing listing from S3", is_flag=True)
@click.pass_obj
@error.handle_exception(handle=(ValueError, ))
def create_listing(cfg: config.Application, ignore_missing_listing: bool):
    s3_bucket = cfg.distribution.s3_bucket
    s3_path = cfg.distribution.s3_path

    # get existing listing file...
    the_listing = db.listing.fetch(bucket=s3_bucket, path=s3_path, create_if_missing=ignore_missing_listing)

    # look for existing DBs in S3
    existing_paths_by_basename = distribution.existing_dbs_in_s3(
        s3_bucket=s3_bucket,
        s3_path=s3_path,
    )

    # determine what basenames are new relative to the listing file and the current S3 state
    new_basenames, missing_basenames = the_listing.basename_difference(
        set(existing_paths_by_basename.keys()),
    )

    if missing_basenames:
        logging.warning(f"missing {len(missing_basenames)} databases in S3 which were in the existing listing file (removing entries in the next listing file)")
        for basename in missing_basenames:
            logging.warning(f"  - {basename}")

    the_listing.remove_by_basename(missing_basenames)

    # add DBs that were discovered in S3 but not already in the listing file
    logging.info(f"discovered {len(new_basenames)} new database candidates to add to the listing")
    for entry in distribution.listing_entries_dbs_in_s3(
        basenames=new_basenames,
        paths_by_basename=existing_paths_by_basename,
        s3_bucket=s3_bucket,
        s3_path=s3_path,
    ):
        the_listing.add(entry)

    # prune the listing to the top X many, by schema, sorted by build date
    # note: we do not delete the entries from S3 in case they need to be referenced again
    the_listing.prune(
        max_age_days=distribution.MAX_DB_AGE,
        minimum_elements=distribution.MINIMUM_DB_COUNT,
    )

    total_entries = sum([len(v) for k, v in the_listing.available.items()])
    logging.info(f"wrote {total_entries} total database entries to the listing")

    listing_file_name = cfg.distribution.listing_file_name
    with open(listing_file_name, "w") as f:
        f.write(the_listing.to_json())

    click.echo(listing_file_name)


@group.command(name="validate", help="validate all supported schema versions are expressed in the listing file")
@click.argument("listing-file")
@click.pass_obj
@error.handle_exception(handle=(ValueError, ))
def validate_listing(cfg: config.Application, listing_file: str):
    with open(listing_file, "r") as f:
        listing_obj = db.Listing.from_json(f.read())

    if not cfg.validate.listing.image:
        raise ValueError("no image specified to validate against")

    if not cfg.validate.listing.minimum_packages:
        raise ValueError("minimum packages must be specified")

    if not cfg.validate.listing.minimum_vulnerabilities:
        raise ValueError("minimum vulnerabilities must be specified")

    if cfg.validate.listing.override_db_schema_version and not cfg.validate.listing.override_grype_version:
        raise ValueError("override grype version must be specified if override db schema version is specified")

    if cfg.validate.listing.override_grype_version and not cfg.validate.listing.override_db_schema_version:
        raise ValueError("ovrerride db schema version must be specified if override grype version is specified")

    override_schema_release = None
    if cfg.validate.listing.override_db_schema_version and cfg.validate.listing.override_grype_version:
        override_schema_release = (cfg.validate.listing.override_db_schema_version, cfg.validate.listing.override_grype_version)

    db.listing.smoke_test(
        listing_obj,
        image=cfg.validate.listing.image,
        override_schema_release=override_schema_release,
        minimum_packages=cfg.validate.listing.minimum_packages,
        minimum_vulnerabilities=cfg.validate.listing.minimum_vulnerabilities,
    )

    click.echo(f"{Format.BOLD}{Format.OKGREEN}Validation passed{Format.RESET}")


@group.command(name="upload", help="upload a listing file to S3")
@click.argument("listing-file")
@click.pass_obj
def upload_listing(cfg: config.Application):
    s3_bucket = cfg.distribution.s3_bucket
    s3_path = cfg.distribution.s3_path

    raise NotImplementedError("uploading listing files is not yet implemented")


