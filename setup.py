from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="falcon-analyzer",
    description="Falcon is a Solidity static analysis framework written in Python 3.",
    url=" ",
    author="",
    version="0.2.28",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "prettytable>=0.7.2",
        "pysha3>=1.0.2",
        "crytic-compile==0.3.3",
        "z3-solver==4.11.2.0",
        "networkx==2.5.1",
        "openai==0.27.8"

    ],
    extras_require={
        "dev": [
            "black==22.3.0",
            "pylint==2.13.4",
            "pytest",
            "pytest-cov",
            "deepdiff",
            "numpy",
            "solc-select>=v1.0.0b1",
        ]
    },
    dependency_links=["git+https://github.com/crytic/crytic-compile.git@master#egg=crytic-compile"],
    license="AGPL-3.0",
    long_description=" ",
    long_description_content_type="text/markdown",
    entry_points={
        "console_scripts": [
            "falcon = falcon.__main__:main",
            "falcon-check-upgradeability = falcon.tools.upgradeability.__main__:main",
            "falcon-find-paths = falcon.tools.possible_paths.__main__:main",
            "falcon-simil = falcon.tools.similarity.__main__:main",
            "falcon-flat = falcon.tools.flattening.__main__:main",
            "falcon-format = falcon.tools.falcon_format.__main__:main",
            "falcon-check-erc = falcon.tools.erc_conformance.__main__:main",
            "falcon-check-kspec = falcon.tools.kspec_coverage.__main__:main",
            "falcon-prop = falcon.tools.properties.__main__:main",
            "falcon-mutate = falcon.tools.mutator.__main__:main",
            "falcon-read-storage = falcon.tools.read_storage.__main__:main",
        ]
    },
)
