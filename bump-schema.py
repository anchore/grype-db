import glob
import os
import re
import shutil
from typing import List

PROCESS_PATH = "./pkg/process"
DEFAULT_SCHEMA_PATH = os.path.join(PROCESS_PATH, "default_schema_version.go")
IMPORT_TEMPLATES = [
    "github.com/anchore/grype-db/pkg/process/{}",
    "github.com/anchore/grype/pkg/db/{}",
]


def get_schema_versions(path: str = PROCESS_PATH) -> List[str]:
    return [os.path.basename(p) for p in glob.glob(path + "/v*") if re.match(r'.*/v\d+$', p)]


def latest_schema_version(versions: List[str]) -> str:
    return "v" + str(max([int(v.replace("v", "")) for v in versions]))


def next_schema_version(version: str):
    return "v" + str(int(version.replace("v", ""))+1)


def replace_in_file(path: str, old: str, new: str):
    with open(path, 'r') as file :
        contents = file.read()
    with open(path, 'w') as file:
        file.write(contents.replace(old, new))


def bump_import_versions(old_version: str, new_version: str):
    path = os.path.join(PROCESS_PATH, new_version)

    for root, dirs, files in os.walk(path):
        for file in files:
            if not file.endswith(".go"):
                continue
            full_path = os.path.join(root, file)

            for import_template in IMPORT_TEMPLATES:
                old_import = import_template.format(old_version)
                new_import = import_template.format(new_version)
                replace_in_file(full_path, old_import, new_import)


def create_new_schema_dir(old_version: str, new_version: str):
    shutil.copytree(
        os.path.join(PROCESS_PATH, old_version),
        os.path.join(PROCESS_PATH, new_version)
    )

    bump_import_versions(old_version, new_version)


def update_default_schema_version(old_version: str, new_version: str):
    for import_template in IMPORT_TEMPLATES:
        old_import = import_template.format(old_version)
        new_import = import_template.format(new_version)
        replace_in_file(DEFAULT_SCHEMA_PATH, old_import, new_import)


def run():
    existing_versions = get_schema_versions()

    if not existing_versions:
        print("could not find any existing schema versions")
        exit(1)

    old_version = latest_schema_version(existing_versions)
    new_version = next_schema_version(old_version)

    print("detected schema versions: ", existing_versions)
    print("latest schema version:    ", old_version)
    print("new schema version:       ", new_version)
    print("generating new schema sources...")
    create_new_schema_dir(old_version, new_version)
    print("updating default schema version...")
    update_default_schema_version(old_version, new_version)
    print("done!")


if __name__ == "__main__":
    run()
