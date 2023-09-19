"""
    Module printing summary of the contract
"""

from falcon.core.declarations import Function
from falcon.printers.abstract_printer import AbstractPrinter
from falcon.utils.myprettytable import MyPrettyTable


class Modifiers(AbstractPrinter):

    ARGUMENT = "modifiers"
    HELP = "Print the modifiers called by each function"

    WIKI = " "

    def output(self, _filename):
        """
        _filename is not used
        Args:
            _filename(string)
        """

        all_txt = ""
        all_tables = []

        for contract in self.falcon.contracts_derived:
            txt = f"\nContract {contract.name}"
            table = MyPrettyTable(["Function", "Modifiers"])
            for function in contract.functions:
                modifiers = function.modifiers
                for call in function.all_internal_calls():
                    if isinstance(call, Function):
                        modifiers += call.modifiers
                for (_, call) in function.all_library_calls():
                    if isinstance(call, Function):
                        modifiers += call.modifiers
                table.add_row([function.name, [m.name for m in set(modifiers)]])
            txt += "\n" + str(table)
            self.info(txt)
            all_txt += txt
            all_tables.append((contract.name, table))

        res = self.generate_output(all_txt)
        for name, table in all_tables:
            res.add_pretty_table(table, name)

        return res
