"""
    Module printing summary of the contract
"""
from falcon.printers.abstract_printer import AbstractPrinter
from falcon.utils.function import get_function_id
from falcon.utils.myprettytable import MyPrettyTable


class FunctionIds(AbstractPrinter):

    ARGUMENT = "function-id"
    HELP = "Print the keccack256 signature of the functions"

    WIKI = " "

    def output(self, _filename):
        """
        _filename is not used
        Args:
            _filename(string)
        """

        txt = ""
        all_tables = []
        for contract in self.falcon.contracts_derived:
            txt += f"\n{contract.name}:\n"
            table = MyPrettyTable(["Name", "ID"])
            for function in contract.functions:
                if function.is_shadowed or function.is_constructor_variables:
                    continue
                if function.visibility in ["public", "external"]:
                    function_id = get_function_id(function.solidity_signature)
                    table.add_row([function.solidity_signature, f"{function_id:#0{10}x}"])
            for variable in contract.state_variables:
                if variable.visibility in ["public"]:
                    sig = variable.solidity_signature
                    function_id = get_function_id(sig)
                    table.add_row([sig, f"{function_id:#0{10}x}"])
            txt += str(table) + "\n"
            all_tables.append((contract.name, table))

        self.info(txt)

        res = self.generate_output(txt)
        for name, table in all_tables:
            res.add_pretty_table(table, name)

        return res
