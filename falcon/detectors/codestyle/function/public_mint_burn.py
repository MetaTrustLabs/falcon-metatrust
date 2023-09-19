# -*- coding:utf-8 -*-
from typing import List

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.modifier_utils import ModifierUtil
from falcon.utils.output import Output


class PublicMintBurnDetector(AbstractDetector):
    ARGUMENT = "public-mint-burn"

    HELP = ' '
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'check public mint method'
    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE

    def _detect(self) -> List[Output]:
        results = []
        for contract in self.contracts:
            if contract.is_interface:
                continue

            for func in contract.functions:
                if any("revert()" in str(node) for node in func.nodes):
                    continue
                if func.is_constructor or func.is_fallback \
                        or func.is_receive or func.view or func.pure \
                        or not func.entry_point:
                    continue

                if func.name in ['mint', 'burn'] and \
                        func.entry_point is not None and \
                        func.visibility in ['external', 'public'] and \
                        not ModifierUtil._has_msg_sender_check_new(func):
                    results.append(self.generate_result(['public mint or burn found in ', func]))
        return results
