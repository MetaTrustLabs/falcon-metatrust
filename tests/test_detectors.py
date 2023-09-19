# -*- coding:utf-8 -*-
import logging
import os
import pathlib
import sys
import unittest
from typing import NamedTuple, Type, Optional, List

from solc_select.solc_select import install_artifacts as install_solc_versions
from solc_select.solc_select import installed_versions as get_installed_solc_versions

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from falcon.detectors.abstract_detector import AbstractDetector
from falcon.falcon import Falcon
from falcon.detectors.core_detectors.price_manipulation_info import PriceManipulationInfo

from falcon.exceptions import FalconError


class Test(NamedTuple):
    detector: Type[AbstractDetector]
    test_file: str
    solc_ver: str
    additional_files: Optional[List[str]] = None


# 测试用例维护
ALL_TESTCASE = [
    Test(
        PriceManipulationInfo,
        "Vault.sol",
        "0.8.2"
    )
]


class TestContracts(unittest.TestCase):

    def setUp(self) -> None:
        installed_solcs = set(get_installed_solc_versions())
        required_solcs = set([test.solc_ver for test in ALL_TESTCASE])
        missing_solcs = list(required_solcs - installed_solcs)
        if missing_solcs:
            install_solc_versions(missing_solcs)

    def _setup_solc(self, solc_version: str):
        env = dict(os.environ)
        env["SOLC_VERSION"] = solc_version
        os.environ.clear()
        os.environ.update(env)


def generate_test(test: Test):
    def _test(self: TestContracts):
        test_sol = pathlib.Path(os.path.abspath(
            os.path.dirname(__file__))) / "detectors" / test.detector.ARGUMENT / test.solc_ver / test.test_file

        if not test_sol.exists():
            raise FalconError(f"{test_sol} doesn't exist")

        self._setup_solc(test.solc_ver)
        sli = Falcon(str(test_sol), solc_disable_warnings=True)
        sli.register_detector(test.detector)

        sli.run_detectors()
        # Add -v to command line to get outputs
        # logging.info(results)
        # We should have found something
        # self.assertTrue(len(results[0]) != 0)

    setattr(TestContracts, f"test_{pathlib.Path(test.test_file).stem}", _test)


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if len(sys.argv) >= 2:
        detector_key = sys.argv[1]
        for test in ALL_TESTCASE:
            if test.detector.ARGUMENT == detector_key:
                generate_test(test)
        del sys.argv[1]
    else:
        for test in ALL_TESTCASE:
            generate_test(test)

    unittest.main()
