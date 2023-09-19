from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IncorrectInheritanceOrderChecker(AbstractDetector):
    """
    IncorrectInheritanceOrderChecker
    """

    ARGUMENT = "incorrect-inheritance-order"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "IncorrectInheritanceOrderChecker"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://swcregistry.io/docs/SWC-125"
    WIKI_TITLE = "Incorrect Inheritance Order Checker"
    WIKI_DESCRIPTION = "Incorrect Inheritance Order Checker"
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    def _detect(self):
        info = []

        for c in self.compilation_unit.contracts:
            inherited_funcs = {}
            for pc in c.inheritance:
                # print("%s => %s" % (c.name, [ p.name for p in c.inheritance ]))
                for f in pc.functions:
                    if f.name not in inherited_funcs:
                        inherited_funcs[f.name] = set([])
                    inherited_funcs[f.name].add(pc)

            # we get leaf pcs of a functon by filtering the parent classes (pcs) who are parents of other pcs 
            # for a given func:
            #   if # of leaf pcs > 1, warn the developer to check potential inheritance order issues
            func2leaf = {}

            for f, pcs in inherited_funcs.items():
                leaf_pcs = set([])

                pclist = list(pcs)
                for i in range(0, len(pclist)):
                    is_leaf = True

                    now_pc = pclist[i]
                    for j in range(0, len(pclist)):
                        if (i != j) and (now_pc in pclist[j].inheritance):
                            is_leaf = False

                    if is_leaf:
                        leaf_pcs.add(now_pc)

                func2leaf[f] = leaf_pcs

            for f, leaf_pcs in func2leaf.items():
                if len(leaf_pcs) > 1:
                    info.extend([c, "%s inherits func %s from %s\n" % (c.name, f, [pc.name for pc in leaf_pcs])])

        return [self.generate_result(info)] if len(info) > 0 else []
