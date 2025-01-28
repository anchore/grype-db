# grype-db

**Application to create a [Grype](https://github.com/anchore/grype) vulnerability database from upstream vulnerability data sources.**

[![GitHub release](https://img.shields.io/github/release/anchore/grype-db.svg)](https://github.com/anchore/grype-db/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/anchore/grype-db/blob/main/LICENSE)
[![Join our Discourse](https://img.shields.io/badge/Discourse-Join-blue?logo=discourse)](https://anchore.com/discourse)

## Installation

**Note**: Currently, Grype-DB is built only for Linux and macOS.

### Recommended

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype-db/main/install.sh | sh -s -- -b /usr/local/bin
```

... or, you can specify a release version and destination directory for the installation:

```
curl -sSfL https://raw.githubusercontent.com/anchore/grype-db/main/install.sh | sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
```

> [!IMPORTANT]  
> You will require the `zstd` utility installed on your system to support the `package` command.

## Usage

`grype-db` takes the following options:

```bash
grype-db [-g] [--dir=DIR] [--schema=SCHEMA] [--skip-validation] [--publish-base-url=URL] [-p PROVIDER ...]
```

### Pulling Data and Building the Database

To pull data from a specific provider or providers and build the database in one step, run `grype-db` with the `-g` flag and specify providers with the `-p` flag:

```sh
grype-db -g -p nvd
```

This example will build the database for the `nvd` provider. Multiple providers can be specified.

If no providers are specified, `grype-db` defaults to all available providers as generated by `vunnel list`. However, note that that accessing GitHub provider data requires a token to authenticate to the GitHub API. See [Getting Started Step-by-Step](https://github.com/anchore/grype-db#getting-started-step-by-step) for more information on adding a GitHub token.)

To download all provider data and build the `vulnerability.db` database, run:

```sh
grype-db -g
```

By default, `grype-db` will download provider data and build the database. To run these steps individually, use the `build` and `pull` subcommands.

### Pulling Provider Data

To pull provider data without building the database:

```sh
grype-db pull -g -p nvd
```

Omit the `-p` flag to target all available providers.

Note that you can skip the `pull` step if you already have a local cache of vulnerability data, such as with `make download-all-provider-cache`.

### Building the Database

Once provider data has been downloaded, run the following to build the database:

```sh
grype-db build -g -p nvd
```

The build command can take the following options:

```sh
grype-db build [-g] [--dir=DIR] [--schema=SCHEMA] [--skip-validation] [-p PROVIDER ...]
```

### Package the Database

You can package the `vulnerability.db`, for example to serve the data or for use in CI. Note that you will need the zstd utility to be installed on your system to usethe `package` subcommand.

To package a built database, run:

```sh
grype-db package
```

This will package any database present in the `build` folder.

The `package` subcommand takes the following options:

```
grype-db package [--dir=DIR] [--publish-base-url=URL]
```

The `package` command archives the `vulnerability.db` file into a `tar.zstd` file. Additionally, a `latest.json`
is generated to aid in serving one or more database archives for downstream consumption, where the consuming application should
use the listing file to discover archives available for download. The base URL used to create the download URL for each
database archive is controlled by the `package.base-url` configuration option.

### Notes on the Cache

The `pull` command downloads and caches vulnerability data from upstream sources (e.g. NIST, redhat, github, canonical, etc.) into
a cache directory. The cache location is a platform dependent XDG directory, however, the location can be overridden with the `cache.dir`
configuration option.

The `build` command processes the cached vuln data generate a `vulnerability.db` sqlite3 file. Additionally, a `metadata.json` file
is created that is used in packaging and curation of the database file .In addition, a `provider-metadata.json` file is created that includes the last successful run date for each provider.

### Cache Commands

To show the current state of the entire vulnerability data cache or a specific `PROVIDER`:

```sh
grype-db cache status [--provider-name=PROVIDER ...]
```

To back up all cached vulnerability data or a specific PROVIDER to a tar.gz file (`PATH`):

```sh
grype-db cache backup [--path=PATH] [--provider-name=PROVIDER]
```

To delete all cached vulnerability data or a specific `PROVIDER`:

```sh
grype-db cache delete [--provider-name=PROVIDER]
```

To restore vulnerability cache from a tar.gz file (`PATH`)

```sh
grype-db cache restore [--path=PATH] [--delete-existing]
```

## Getting Started Step-by-Step

If you're running `grype-db` for the first time, you can set up using the following steps.

First, [create a GitHub access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) to authenticate to the GitHub API. (Tokens can be generated on [this GitHub settings page](https://github.com/settings/tokens).) No specific permissions are needed. Using restrictive permissions settings and creating a short-lived token is highly recommended.

Set your token as an environment variable:

```sh
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Create and set a working directory:

```sh
mkdir -p ~/vulnerability-data && cd $_
```

Create a Python virtual environment and activate it:

```sh
python -m venv venv && source venv/bin/activate
```

Install [vunnel](https://github.com/anchore/vunnel):

```sh
pip install vunnel
```

Now install `grype-db` as a binary in the working directory. (Note that this will not place `grype-db` on your path.)

```sh
curl -sSfL https://raw.githubusercontent.com/anchore/grype-db/main/install.sh | sh -s -- -b .
```

Create a configuration file for `grype-db` using the following here document. The command will automatically add the GitHub token you set earlier to the config, so no manual replacement is needed.

```sh
cat << EOF > ~/vulnerability-data/.grype-db.yaml
provider:
  vunnel:
    executor: local
    generate-configs: true
    env:
      GITHUB_TOKEN: $GITHUB_TOKEN
EOF
```

Build the database from all providers. (Note that this command can take significant time to complete.)

```sh
./grype-db -g
```

Once this command completes, you should have `data` and `build` folders with downloaded data and a built `vulnerability.db` file, among other contents.

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

provider:
  # where to read and write all provider data. The state must be oriented as described 
  # in https://github.com/anchore/vunnel/tree/main/schema/provider-workspace-state .
  # Note: all location references under `providers` should be relative to this directory
  # same as GRYPE_DB_PROVIDER_ROOT env var
  root: ./data

  # names of providers to filter down to while running
  # same as -p
  include-filter: []
  
  vunnel:
    # how to execute vunnel. Options are:
    #  - "docker" (default): execute vunnel in a docker container
    #  - "local": execute vunnel on the host from what is in your $PATH
    executor: docker
    
    # the docker image to use when executing vunnel with executor=docker
    docker-tag: latest
    docker-image: ghcr.io/anchore/vunnel
    
    # generate additional provider configuration files based on the "vunnel list" command
    # same as -g ; GRYPE_DB_GENERATE_CONFIGS env var
    generate-configs: true
    
    # providers to exclude from the "vunnel list" command (only applies when generate-configs=true)
    exclude-providers:
      - centos
    
    # environment variables to set when executing vunnel
    env: {}
    
  # manually crafted provider configurations. (advanced use only)
  configs: []

pull:
  # the number of concurrent workers to use when pulling and processing data
  parallelism: 1

build:
  # where to place the built SQLite DB that is built from the "build" command
  # same as --dir; GRYPE_DB_BUILD_DIR env var
  dir: "./build"

  # the DB schema version to build
  # same as --schema-version; GRYPE_DB_BUILD_SCHEMA_VERSION env var
  schema-version: 5

  # skip validation of the provider state
  skip-validation: false

package:
  # this is the base URL that is referenced in the listing file created during the "package" command
  # same as GRYPE_DB_PACKAGE_PUBLISH_BASE_URL env var
  publish-base-url: "https://localhost:8080/grype/databases"

  # limit the providers to pull based off of this list. (empty list means pull all providers)
  provider-names: []

```
