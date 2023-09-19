"""
    Check that the same pragma is used in all the files
"""

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.formatters.attributes.constant_pragma import custom_format


class ConstantPragma(AbstractDetector):
    """
    Check that the same pragma is used in all the files
    """

    ARGUMENT = "different-pragma"
    HELP = "If different pragma directives are used"
    IMPACT = DetectorClassification.OPTIMIZATION
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "

    WIKI_TITLE = "Different pragma directives are used"
    WIKI_DESCRIPTION = "Detect whether different Solidity versions are used."
    WIKI_RECOMMENDATION = "Use one Solidity version."

    def _detect(self):
        results = []
        pragma = self.compilation_unit.pragma_directives
        versions = [p.version for p in pragma if p.is_solidity_version]
        versions = sorted(list(set(versions)))

        if len(versions) > 1:
            info = ["Different versions of Solidity are used:\n"]
            info += [f"\t- Version used: {[str(v) for v in versions]}\n"]

            for p in pragma:
                info += ["\t- ", p, "\n"]

            res = self.generate_result(info)

            results.append(res)

        return results

    @staticmethod
    def _format(falcon, result):
        custom_format(falcon, result)
