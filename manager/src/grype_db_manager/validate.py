
import json
from importlib.resources import files
from functools import lru_cache

from yardstick.cli import config as ycfg
from yardstick import capture

from grype_db_manager import grypedb, sbom

RESULT_SET = "db-validation"




def validate(cfg: ycfg.Application, db_uuid: str, root_dir: str):

    dbm = grypedb.DBManager(root_dir=root_dir)
    dbm.get_db_info(db_uuid)

    # capture results, unless already captured
    sbom.download(cfg=cfg, result_set=RESULT_SET)
    capture.result_set(result_set=RESULT_SET, scan_requests=cfg.result_sets[RESULT_SET].scan_requests())

    # validate results, (relative comparison with label context applied)


@lru_cache
def _get_schema_mapping() -> dict[str, str]:
    content = files('grype_db_manager.data').joinpath('grype-schema-version-mapping.json').read_text()
    return json.loads(content)


def grype_version(schema_version: int) -> str:
    mapping = _get_schema_mapping()
    return mapping[str(schema_version)]

