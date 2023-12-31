import logging

from falcon.ir.operations import EventCall
from falcon.utils import output

logger = logging.getLogger("Falcon-conformance")


def events_safeBatchTransferFrom(contract, ret):
    function = contract.get_function_from_signature(
        "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)"
    )
    events = [
        {
            "name": "TransferSingle",
            "parameters": ["address", "address", "address", "uint256", "uint256"],
        },
        {
            "name": "TransferBatch",
            "parameters": ["address", "address", "address", "uint256[]", "uint256[]"],
        },
    ]

    event_counter_name = 0
    event_counter_parameters = 0
    if function:
        for event in events:
            for ir in function.all_falconir_operations():
                if isinstance(ir, EventCall) and ir.name == event["name"]:
                    event_counter_name += 1
                    if event["parameters"] == [str(a.type) for a in ir.arguments]:
                        event_counter_parameters += 1
    if event_counter_parameters == 1 and event_counter_name == 1:
        txt = "[✓] safeBatchTransferFrom emit TransferSingle or TransferBatch"
        logger.info(txt)
    else:
        txt = "[ ] safeBatchTransferFrom must emit TransferSingle or TransferBatch"
        logger.info(txt)

        erroneous_erc1155_safeBatchTransferFrom_event = output.Output(txt)
        erroneous_erc1155_safeBatchTransferFrom_event.add(contract)
        ret["erroneous_erc1155_safeBatchTransferFrom_event"].append(
            erroneous_erc1155_safeBatchTransferFrom_event.data
        )


def check_erc1155(contract, ret, explored=None):
    if explored is None:
        explored = set()

    explored.add(contract)

    events_safeBatchTransferFrom(contract, ret)

    for derived_contract in contract.derived_contracts:
        check_erc1155(derived_contract, ret, explored)

    return ret
