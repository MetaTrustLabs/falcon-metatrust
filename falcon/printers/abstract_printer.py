import abc
from logging import Logger

from typing import TYPE_CHECKING, Union, List, Optional, Dict

from falcon.utils import output
from falcon.utils.output import SupportedOutput

if TYPE_CHECKING:
    from falcon import Falcon


class IncorrectPrinterInitialization(Exception):
    pass


class AbstractPrinter(metaclass=abc.ABCMeta):
    ARGUMENT = ""  # run the printer with falcon.py --ARGUMENT
    HELP = ""  # help information

    WIKI = ""

    def __init__(self, falcon: "Falcon", logger: Logger) -> None:
        self.falcon = falcon
        self.contracts = falcon.contracts
        self.filename = falcon.filename
        self.logger = logger

        if not self.HELP:
            raise IncorrectPrinterInitialization(
                f"HELP is not initialized {self.__class__.__name__}"
            )

        if not self.ARGUMENT:
            raise IncorrectPrinterInitialization(
                f"ARGUMENT is not initialized {self.__class__.__name__}"
            )

        if not self.WIKI:
            raise IncorrectPrinterInitialization(
                f"WIKI is not initialized {self.__class__.__name__}"
            )

    def info(self, info: str) -> None:
        if self.logger:
            self.logger.info(info)

    def generate_output(
        self,
        info: Union[str, List[Union[str, SupportedOutput]]],
        additional_fields: Optional[Dict] = None,
    ) -> output.Output:
        if additional_fields is None:
            additional_fields = {}
        printer_output = output.Output(info, additional_fields)
        printer_output.data["printer"] = self.ARGUMENT

        return printer_output

    @abc.abstractmethod
    def output(self, filename: str) -> output.Output:
        pass
