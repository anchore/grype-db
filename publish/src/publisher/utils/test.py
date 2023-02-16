import logging
from dataclasses import dataclass
from typing import Dict, List

import publisher.utils.grype as grype
import publisher.utils.builder as builder


@dataclass
class Case:
    grype: "grype.Grype"
    builder: "builder.GrypeDbBuilder"
    schema_version: int


class Runner:
    def __init__(self, user_input: str, golden_report_path: str):
        self.cases: Dict[int, Case] = {}
        self.user_input = user_input
        self.golden_report_path = golden_report_path

    def add_case(self, case: Case):
        existing_case = self.cases.get(case.schema_version)
        if not existing_case:
            self.cases[case.schema_version] = case
            return

        # only keep the latest version for schema versions already covered
        if existing_case.grype.release.version < case.grype.release.version:
            self.cases[case.schema_version] = case

    def schema_versions(self) -> List[int]:
        return list(self.cases.keys())

    def run(self):
        if len(self.cases) == 0:
            logging.error("no test cases found!")
            return False

        for schema_version, case in self.cases.items():
            # note: failing tests should raise exceptions
            self.run_test_case(case=case)

    def run_test_case(self, case: Case):
        logging.info(
            f"running acceptance test for schema={case.schema_version} grype={case.grype.release}"
        )
        with open(self.golden_report_path, "r") as f:
            golden_report_content = f.read()

        try:
            # import the DB to a preconfigured destination
            db_path = case.builder.db_path(scheme_version=case.schema_version)
            case.grype.import_db(db_path=db_path)

            output = case.grype.run(user_input=self.user_input)

            # run the test and ensure the output is "good enough"
            current_run = grype.Report(report_contents=output)
            golden_run = grype.Report(report_contents=golden_report_content)

            # either raises an error or returns nothing based on the comparison
            golden_run.compare(other=current_run)

        except Exception as exc:
            logging.error(f"failed test case={case.grype.release}: {str(exc)}")
            raise
