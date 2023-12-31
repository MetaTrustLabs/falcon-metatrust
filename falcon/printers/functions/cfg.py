from falcon.printers.abstract_printer import AbstractPrinter


class CFG(AbstractPrinter):

    ARGUMENT = "cfg"
    HELP = "Export the CFG of each functions"

    WIKI = " "

    def output(self, filename):
        """
        _filename is not used
        Args:
            _filename(string)
        """

        info = ""
        all_files = []
        for contract in self.contracts:
            if contract.is_top_level:
                continue
            for function in contract.functions + contract.modifiers:
                if filename:
                    new_filename = f"{filename}-{contract.name}-{function.full_name}.dot"
                else:
                    new_filename = f"{contract.name}-{function.full_name}.dot"
                info += f"Export {new_filename}\n"
                content = function.falconir_cfg_to_dot_str()
                with open(new_filename, "w", encoding="utf8") as f:
                    f.write(content)
                all_files.append((new_filename, content))

        self.info(info)

        res = self.generate_output(info)
        for filename_result, content in all_files:
            res.add_file(filename_result, content)
        return res
