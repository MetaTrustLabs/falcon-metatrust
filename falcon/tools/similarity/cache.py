import sys

try:
    import numpy as np
except ImportError:
    print("ERROR: in order to use falcon-simil, you need to install numpy")
    print("$ pip3 install numpy --user\n")
    sys.exit(-1)


def load_cache(infile, nsamples=None):
    cache = {}
    with np.load(infile, allow_pickle=True) as data:
        array = data["arr_0"][0]
        for i, (x, y) in enumerate(array):
            cache[x] = y
            if i == nsamples:
                break

    return cache


def save_cache(cache, outfile):
    np.savez(outfile, [np.array(cache)])
