import argparse
import subprocess
from falcon.somo.solmoctor.core import SlitherParser
from falcon.somo.solmoctor.solmoctor import SolMoctor


class SoMoRun:
    def __init__(self) -> None:
        # Set fixed input and settings
        self.code = "../example/contract.sol"
        self.setting = "../example/contract.json"

        self.solc_select, self.solc = self._get_solc()
        self.parser: SlitherParser = SlitherParser(self.solc)
        self.somo = SolMoctor()

    def _get_solc(self) -> str:
        # Obtain essential components relying on.
        result = subprocess.run(["which", "solc-select"], stdout=subprocess.PIPE)
        if result.returncode != 0:
            print("Error: Can not find `solc-select`.")
            exit(-1)
        solc_select = result.stdout.decode("utf-8").replace("\n", "")

        result = subprocess.run(["which", "solc"], stdout=subprocess.PIPE)
        if result.returncode != 0:
            print("Error: Can not find `solc`.")
            exit(-1)
        solc = result.stdout.decode("utf-8").replace("\n", "")

        return solc_select, solc

    def run(self):
        # parse the contract first
        contract, slither = self.parser.parse(self.code, self.setting)
        # print(contract)
        status, result = self.somo.check(contract, slither)
        print(status)
        print(result)


if __name__ == '__main__':
    SoMoRun().run()
