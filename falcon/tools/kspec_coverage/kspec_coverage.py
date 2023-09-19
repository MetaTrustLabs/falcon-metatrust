from falcon.tools.kspec_coverage.analysis import run_analysis
from falcon import Falcon


def kspec_coverage(args):

    contract = args.contract
    kspec = args.kspec

    falcon = Falcon(contract, **vars(args))

    compilation_units = falcon.compilation_units
    if len(compilation_units) != 1:
        print("Only single compilation unit supported")
        return
    # Run the analysis on the Klab specs
    run_analysis(args, compilation_units[0], kspec)
