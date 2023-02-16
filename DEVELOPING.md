# Developing

## Getting started

This codebase is primarily Go, however, there are also Python scripts critical to the daily DB publishing process as
well as acceptance testing. You will require the following:

- Python 3.8+ installed on your system. Consider using [pyenv](https://github.com/pyenv/pyenv) if you do not have a 
  preference for managing python interpreter installations.
  

- [Poetry](https://python-poetry.org/) installed for dependency and virtualenv management for python dependencies, to install:

   ```bash
   curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | python -
   ```

- [Git LFS](https://git-lfs.github.com/) installed for managing test fixtures in the repo, once installed initialze with:

   ```bash
   git lfs install
   ```

To download go tooling used for static analysis and dependent go modules run the following:

```bash
make bootstrap
```

## Getting an initial vulnerability data cache

In order to build a grype DB you will need a local cache of vulnerability data:

```bash
make download-all-provider-cache
```

This will populate the `./data` directory locally with everything needed to run `grype-db build` (without needing to run `grype-db pull`).

## Running tests

To unit test the Go code and unit test the publisher python scripts:

```bash
make unit
```

To verify that all supported schema versions interop with grype run:

```bash
make acceptance
# Note: this may take a while... go make some coffee.
```


## Create a new DB schema

1. Create a new `v#` schema package in the `grype` repo (within `pkg/db`)
2. Create a new `v#` schema package in the `grype-db` repo (use the `bump-schema.py` helper script) that uses the new changes from `grype-db`
3. Modify the `grype-schema-version-mapping.json` to pin the last-latest version to a specific version of grype and add the new schema version pinned to the "main" branch of grype (or a development branch)
4. Update all references in `grype` to use the new schema
5. Use the [Staging DB Publisher](https://github.com/anchore/grype-db/actions/workflows/staging-db-publisher.yaml) workflow to test your DB changes with grype in a flow similar to the daily DB publisher workflow


## Making a staging DB

While developing a new schema version it may be useful to get a DB built for you by the [Staging DB Publisher](https://github.com/anchore/grype-db/actions/workflows/staging-db-publisher.yaml) GitHub Actions workflow.
This code exercises the same code as the Daily DB Publisher, with the exception that only a single schema is built and is validated against a given development branch of grype.
When these DBs are published you can point grype at the proper listing file like so:

```bash
$ GRYPE_DB_UPDATE_URL=https://toolbox-data.anchore.io/grype/staging-databases/listing.json grype centos:8 ...
```

## Architecture

`grype-db` is essentially an application that extracts information from upstream vulnerability data providers,
transforms it into smaller records targeted for grype consumption, and loads the individual records into a new SQLite DB.

```
~~~~~ "Pull" ~~~~~      ~~~~~~~~~~~~~~~~~~ "Build" ~~~~~~~~~~~~~~~~     ~~ "Package" ~~

┌─────────────────┐     ┌───────────────────┐     ┌───────────────┐     ┌─────────────┐
│ Pull vuln data  │     │ Transform entries │     │ Load entries  │     │ Package DB  │
│ from upstream   ├────►│                   ├────►│ into new DB   ├────►│             │
└─────────────────┘     └───────────────────┘     └───────────────┘     └─────────────┘
```

What makes `grype-db` a little more unique than a typical ETL job is the extra responsibility of needing to
transform the most recent vulnerability data shape (defined in the [vunnel repo](https://github.com/anchore/vunnel/tree/main/schema/vulnerability)) to all supported DB schema versions. 
From the perspective of the Daily DB Publisher workflow, (abridged) execution looks something like this:

```
 ┌─────────────────┐          ┌──────────────┐     ┌────────────────┐
 │ Pull vuln data  ├────┬────►│ Build V1 DB  │────►│ Package V1 DB  │ ...
 └─────────────────┘    │     └──────────────┘     └────────────────┘
                        │     ┌──────────────┐     ┌────────────────┐
                        ├────►│ Build V2 DB  │────►│ Package V2 DB  │ ...
                        │     └──────────────┘     └────────────────┘
                        │     ┌──────────────┐     ┌────────────────┐
                        ├────►│ Build V3 DB  │────►│ Package V3 DB  │ ...
                        │     └──────────────┘     └────────────────┘
                        ...
```

In order to support multiple DB schemas easily from a code-organization perspective the following abstractions exist:


- **Provider**: responsible for providing raw vulnerability data files that are cached locally for later processing.


- **Processor**: responsible for unmarshalling any entries given by the `Provider`, passing them into `Transformers`, and
  returning any resulting entries. Note: the object definition is schema-agnostic but instances are schema-specific
  since Transformers are dependency-injected into this object.


- **Transformer**: Takes raw data entries of a specific [vunnel-defined schema](https://github.com/anchore/vunnel/tree/main/schema/vulnerability)
  and transforms the data into schema-specific entries to later be written to the database. Note: the object definition 
  is schema-specific, encapsulating `grypeDB/v#` specific objects within schema-agnostic `Entry` objects.


- **Entry**: Encapsulates schema-specific database records produced by `Processors`/`Transformers` (from the provider data) 
  and accepted by `Writers`.


- **Writer**: Takes `Entry` objects and writes them to a backing store (today a SQLite database). Note: the object
 definition is schema-specific and typically references `grypeDB/v#` schema-specific writers.


All the above abstractions are defined in the `pkg/data` Go package and are used together commonly in the following flow:

```
                       ┌────────────────────────────────────────────┐
                cache  │data.Processor                              │
 ┌─────────────┐ file  │ ┌────────────┐       ┌───────────────────┐ │ []data.Entry  ┌───────────┐     ┌───────────────────────┐
 │data.Provider├──────►│ │unmarshaller├──────►│v# data.Transformer│ ├──────────────►│data.Writer├────►│grypeDB/v#/writer.Write│
 └─────────────┘       │ └────────────┘       └───────────────────┘ │               └───────────┘     └───────────────────────┘
                       └───────────────────────────────────────────-┘
```

Where there is a `data.Provider` for each upstream data source (e.g. canonical, redhat, github, NIST, etc.), 
a `data.Processor` for every vunnel-defined data shape (github, os, msrc, nvd, etc... defined in the [vunnel repo](https://github.com/anchore/vunnel/tree/main/schema/vulnerability)), 
a `data.Transformer` for every processor and DB schema version pairing, and a `data.Writer` for every DB schema version.

From a Go package organization perspective, the above abstractions are organized as follows:

```
grype-db/
└── pkg
    ├── data                      # common data structures and objects that define the ETL flow
    ├── process
    │    ├── processors           # common data.Processors to call common unmarshallers and pass entries into data.Transformers
    │    ├── v1
    │    │    ├── processors.go   # wires up all common data.Processors to v1-specific data.Transformers
    │    │    ├── writer.go       # v1-specific store writer
    │    │    └── transformers    # v1-specific transformers
    │    ├── v2
    │    │    ├── processors.go   # wires up all common data.Processors to v2-specific data.Transformers
    │    │    ├── writer.go       # v2-specific store writer
    │    │    └── transformers    # v2-specific transformers
    │    └── ...more schema versions here...
    └── provider                  # common code to pull, unmarshal, and cache updstream vuln data into local files
        └── ...

```


### DB structure and definitions

The definitions of what goes into the database and how to access it (both reads and writes) live in the public `grype`
repo under the `db` package. Responsibilities of `grype` (not `grype-db`) include (but are not limited to):

- What tables are in the database
- What columns are in each table
- How each record should be serialized for writing into the database
- How records should be read/written from/to the database
- Providing rich objects for dealing with schema-specific data structures
- The name of the SQLite DB file within an archive
- The definition of a listing file and listing file entries

The purpose of `grype-db` is to use the definitions from `grype.db` and the upstream vulnerability data to 
create DB archives and make them publicly available for consumption via grype.


### DB listing file

The listing file contains URLs to grype DB archives that are available for download, organized by schema version, and 
ordered by latest-date-first.
The definition of the listing file resides in `grype`, however, it is the responsibility of the grype-db repo
to generate DBs and re-create the listing file daily.
As long as grype has been configured to point to the correct listing file, the DBs can be stored separately from the
listing file, be replaced with a running service returning the listing file contents, or can be mirrored for systems 
behind an air gap.


### Getting a grype DB out to OSS users (daily)

There are two workflows that drive getting a new grype DB out to OSS users:
1. The daily data sync workflow, which uses [vunnel](https://github.com/anchore/vunnel) to pull upstream vulnerability data.
2. The daily DB publisher workflow, which uses builds and publishes a grype DB from the data obtained in the daily data sync workflow.


#### Daily data sync workflow

**This workflow takes the upstream vulnerability data (from canonical, redhat, debian, NVD, etc), processes it, and
writes the results to the OCI repos.**

```
┌──────────────┐         ┌──────────────────────────────────────────────────────────┐
│ Pull alpine  ├────────►│ Publish to ghcr.io/anchore/grype-db/data/alpine:<date>   │
└──────────────┘         └──────────────────────────────────────────────────────────┘
┌──────────────┐         ┌──────────────────────────────────────────────────────────┐
│ Pull amazon  ├────────►│ Publish to ghcr.io/anchore/grype-db/data/amazon:<date>   │
└──────────────┘         └──────────────────────────────────────────────────────────┘
┌──────────────┐         ┌──────────────────────────────────────────────────────────┐
│ Pull debian  ├────────►│ Publish to ghcr.io/anchore/grype-db/data/debian:<date>   │
└──────────────┘         └──────────────────────────────────────────────────────────┘
┌──────────────┐         ┌──────────────────────────────────────────────────────────┐
│ Pull github  ├────────►│ Publish to ghcr.io/anchore/grype-db/data/github:<date>   │
└──────────────┘         └──────────────────────────────────────────────────────────┘
┌──────────────┐         ┌──────────────────────────────────────────────────────────┐
│ Pull nvd     ├────────►│ Publish to ghcr.io/anchore/grype-db/data/nvd:<date>      │
└──────────────┘         └──────────────────────────────────────────────────────────┘
... repeat for all upstream providers ...
```

Once all providers have been updated a single vulnerability cache OCI repo is updated with all of the latest vulnerability data at `ghcr.io/anchore/grype-db/data:<date>`. This repo is what is used downstream by the DB publisher workflow to create grype DBs.

The in-repo `.grype-db.yaml` and `.vunnel.yaml` configurations are used to define the upstream data sources, how to obtain them, and where to put the results locally.


#### Daily DB publishing workflow

**This workflow takes the latest vulnerability data cache, builds a grype DB, and publishes it for general consumption.**

The `publish/` directory contains all code responsible for driving the Daily DB Publisher workflow, generating DBs
for all supported schema versions and making them available to the public. The publishing process is made of four steps 
(depicted and described below):

```
~~~~~ 1. Pull ~~~~~      ~~~~~~~~~~~~~ 2. Generate ~~~~~~~~~~~~     ~~ 3. Upload DBs ~~     ~~ 4. Upload Listing ~~

┌─────────────────┐      ┌──────────────┐     ┌───────────────┐     ┌────────────────┐      ┌─────────────────────┐
│ Pull vuln data  ├──┬──►│ Build V1 DB  ├────►│ Package V1 DB ├────►│ Upload Archive ├──┬──►│ Update listing file │
└─────────────────┘  │   └──────────────┘     └───────────────┘     └────────────────┘  │   └─────────────────────┘
  (from the daily    │   ┌──────────────┐     ┌───────────────┐     ┌────────────────┐  │
   sync workflow     ├──►│ Build V2 DB  ├────►│ Package V2 DB ├────►│ Upload Archive ├──┤
   output)           │   └──────────────┘     └───────────────┘     └────────────────┘  │
                     │                                                                  │
                     └──►      ...repeat for as many DB schemas are supported...      ──┘
```

**Note: Running these steps locally may result in publishing a locally generated DB to production, which should never be done.**

1. **pull**: Download the latest vulnerability data from various upstream data sources into a local cache directory. 
   In CI, this is invoked from the root of the repo:

   ```bash
   # from the repo root
   GRYPE_DB_BUILDER_CACHE_DIR=publish/cache go run main.go pull -vv
   ```

   Note that all pulled vuln data is cached into the `publish/cache` directory.


2. **generate**: Build and package a DB from the cached vuln data for a specific DB schema version:

   ```bash
   # from publish/
   poetry run publisher generate --schema-version <version>
   ```

   This call needs to be repeated for all schema versions that are supported (see the `grype-schema-version-mapping.json`
   file in the root of the repo). During this step all DBs and DB archives generated are stored in the `publish/build` directory.
   Once built, DBs are subjected to testing against grype. Each DB is imported by grype, grype is invoked with a test
   image, and the result is compared against a golden test-fixture saved at `publish/test-fixtures`. If the test-fixture
   and the actual report obtained from grype differ significantly, then the script fails.
   Once the comparison test passes, the DB archive is moved from the `publish/build` directory to the `publish/stage`
   directory.


3. **upload-dbs**: All DB archives found in the `publish/stage` directory are uploaded to S3.

   ```bash
   # from publish/
   ./upload-dbs.sh <bucket> <s3-path>
   ```

   Note: only the DB archives are uploaded to S3, the listing file has not been touched. This means that though the
   uploaded DBs are now publicly accessible, installations of grype will not attempt to use the DBs.


4. **upload-listing**: Generate and upload a new listing file to S3 based on the existing listing file and newly
   discovered DB archives already uploaded to S3.

   ```bash
   # from publish/
   poetry run publisher upload-listing --s3-bucket <bucket> --s3-path <s3-path>
   ```
   
   During this step the locally crafted listing file is tested against installations of grype. The correctness of the
   reports are NOT verified (since this was done in a previous step), however, in order to pass the scan must have
   a non-zero count of matches found.

   Once the listing file has been uploaded user-facing grype installations should pick up that there are new DBs available to download.


#### FAQ for daily DB generation

**1. The "generate DB" step fails with "RuntimeError: failed quality gate: vulnerabilities not within tolerance"...**

The "generate DB" step validates the DB against a test fixture in `publish/test-fixtures`. This fixture needs to be
periodically updated with the latest expected set of vulnerabilities. This process should probably be one day updated
to ignore CVEs after a certain year to aid in not needing to update this test fixture that frequently.

To easily update the test fixtures (and similar ones used for acceptance tests):
```
make update-test-fixtures
```

If using an M1 use
```
arch -x86_64 make update-test-fixtures
```
This is necessary because old versions of Grype didn't release arm64 binaries. 
