from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VersionOnly(AbstractDetector):
    """
    Check if confirm solc is used
    """

    ARGUMENT = "version-only"
    HELP = "Solidity version should be confirmed"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "
    WIKI_TITLE = "Solidity version"
    # region wiki_description
    WIKI_DESCRIPTION = "Solidity version should be confirmed "
    # endregion wiki_description
    # region wiki_recommendation
    WIKI_RECOMMENDATION = ".."
    # endregion wiki_recommendation
    WIKI_EXPLOIT_SCENARIO = ".."

    def _detect(self):
        """
        Detects pragma wheather includes ^, >=, <=.
        """
        # Detect all version related pragmas and check if they are disallowed.
        results = []
        pragma = self.compilation_unit.pragma_directives
        KEY_DETECT = ['^', '>=', '<=', '>', '<']

        ret = []
        for p in pragma:
            # Skip any pragma directives which do not refer to version
            if len(p.directive) < 1 or p.directive[0] != "solidity":
                continue
            for key_s in KEY_DETECT:
                if key_s in str(p.name):
                    ret.append(self.generate_result([f"\tPragma confirmed better, here is {p}. ", p, '\n']))
        results.extend(ret) if ret else None

        return results
