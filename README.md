# grype-db
Application to create a vulnerability database from upstream vulnerability data sources.

## Usage

To pull the vulnerability source data, build the `vulnerability.db` file, and package the database into a `tar.gz` run the following:
```bash
# Pull all upstream vulnerability data sources to local cache
grype-db pull

# Build a SQLite DB from the vulnerability data for a particular schema version
grype-db build [--dir=DIR] [--schema=SCHEMA] [--skip-validation]

# Package the already built DB file into an archive ready for upload and serving
grype-db package [--dir=DIR] [--publish-base-url=URL]
```

The `pull` command downloads and caches vulnerability data from upstream sources (e.g. NIST, redhat, github, canonical, etc.) into
a cache directory. The cache location is a platform dependent XDG directory, however, the location can be overridden with the `cache.dir`
configuration option. The default configuration is to use [vunnel](https://github.com/anchore/vunnel) to fetch and 
process the vulnerability data.

**note: you can skip the `pull` step if you already have a local cache of vulnerability data (with `make download-all-provider-cache`).**

The `build` command processes the cached vuln data generate a `vulnerability.db` sqlite3 file. Additionally, a `metadata.json`
is created that is used in packaging and curation of the database file by this application and downstream consuming applications.

The `package` command archives the `vulnerability.db` and `metadata.json` files into a `tar.gz` file. Additionally, a `listing.json`
is generated to aid in serving one or more database archives for downstream consumption, where the consuming application should
use the listing file to discover available archives available for download. The base URL used to create the download URL for each
database archive is controlled by the `package.base-url` configuration option.

You can additionally manage vulnerability data cache with the following commands:
```bash
# backup all cached vulnerability data or a specific PROVIDER to a tar.gz file (PATH)
grype-db cache backup [--path=PATH] [--provider-name=PROVIDER]

# delete all cached vulnerability data or a specific PROVIDER
grype-db cache delete [--provider-name=PROVIDER]

# restore vulnerability cache from a tar.gz file (PATH)
grype-db cache restore [--path=PATH] [--delete-existing]

# show the current state of the all vulnerability data cache or a specific PROVIDER
grype-db cache status [--provider-name=PROVIDER ...]
```

## DB Schemas

This repo supports building databases for all supported versions of grype, even when the data shape has changed.
For every change in the data shape over time, a new schema is created (see the DEVELOPING.md for details on how to bump the schema).

**For every schema grype-db supports, we build a DB for that schema nightly. To reduce nightly DB maintenance, try to keep the schema bumps to a minimum during development.**

Once a schema has been created, the previous schema should be considered locked unless making bug fixes or updates related to [vunnel](https://github.com/anchore/vunnel), or otherwise upstream data shape changes.

If the development being done requires any of the following, then a **new schema is required to be created** (over further developing the current schema):
- If a previous version of grype using the same schema would not function with the new changes
- If the current version of grype using a previously published database (but still the same schema) would not function with the new changes

Where "would not function" means either grype will error out during processing, or the results are otherwise compromised (e.g. missing data that otherwise could/should have been found and reported).

The following kinds of changes **do not necessarily require a new schema**:
- Adding a new data source
- Removing an existing data source (as long as the grype matchers are not requiring its presence)

There are plenty of grey areas between these cases (e.g. changing the expected set of values for a field, or changing the semantics for a column) --use your best judgement.

This repo is responsible for publishing DBs with the latest vulnerability data for every supported schema daily.
This is achieved with the [Daily Data Sync](https://github.com/anchore/grype-db/actions/workflows/daily-data-sync.yaml) and [Daily DB Publisher](https://github.com/anchore/grype-db/actions/workflows/daily-db-publisher.yaml) GitHub Actions workflows.
Which schemas are built and which grype versions are used to verify functionality is controlled with the `grype-schema-version-mapping.json` file in the root of this repo 
(see the DEVELOPING.md for more details). 

## Configuration

```yaml
# suppress all output
# same as -q ; GRYPE_DB_QUIET env var
quiet: false

log:
  # the log level; note: detailed logging suppress the ETUI
  # same as GRYPE_DB_LOG_LEVEL env var
  level: "error"

  # location to write the log file (default is not to have a log file)
  # same as GRYPE_DB_LOG_FILE env var
  file: ""

cache:
  # where the root cache directory is
  # same as GRYPE_DB_CACHE_DIR env var
  dir: "$XDG_CACHE/grype-db"

pull:
  # the number of concurrent workers to use when pulling and processing data
  parallelism: 1
  
  # the location where all provider state is stored. The state must be oriented as described 
  # in https://github.com/anchore/vunnel/tree/main/schema/provider-workspace-state .
  # Note: all location references under `providers` should be relative to this directory
  root: ./data
  
  # a list of provider configurations, for example:
  #
  #     providers:
  #       - name: nvd
  #       - name: alpine
  #       - name: amazon
  #
  # this will populate the `.root` directory with the results.
  # You can also manually craft a similar configuration with the "external" provider:
  #
  #     providers:
  #       - name: nvd
  #         type: external
  #         config:
  #           cmd: vunnel -vv run nvd
  #           path: nvd/metadata.json
  #
  #       - name: alpine
  #         type: external
  #         config:
  #           cmd: vunnel -vv run alpine
  #           path: alpine/metadata.json
  #
  #       - name: amazon
  #         type: external
  #         config:
  #           cmd: vunnel -vv run amazon
  #           path: amazon/metadata.json
  #
  providers: []

build:
  # where to place the built SQLite DB that is built from the "build" command
  # same as GRYPE_DB_BUILD_DIR env var
  dir: "./build"

  # the DB schema version to build
  # same as GRYPE_DB_BUILD_SCHEMA_VERSION env var
  schema-version: 5

package:
  # this is the base URL that is referenced in the listing file created during the "package" command
  # same as GRYPE_DB_PACKAGE_PUBLISH_BASE_URL env var
  publish-base-url: "https://toolbox-data.anchore.io/grype/databases"
```