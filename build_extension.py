"""Build R_Datalib (pydatalib) Python extesion."""

import os

from setuptools import Extension
from setuptools.command import build_ext


def build(setup_kwargs: dict):
    """Python extension build entrypoint."""
    os.environ["_CC_CCMODE"] = "1"
    os.environ["_CXX_CCMODE"] = "1"
    os.environ["_C89_CCMODE"] = "1"
    os.environ["_CC_EXTRA_ARGS"] = "1"
    os.environ["_CXX_EXTRA_ARGS"] = "1"
    os.environ["_C89_EXTRA_ARGS"] = "1"
    os.environ["CC"] = "xlc"
    os.environ["CXX"] = "xlc++"
    setup_kwargs.update(
        {
            "ext_modules": [
                Extension(
                    "cpydatalib",
                    sources=[
                        "pydatalib/c/keyring_py.c",
                        "pydatalib/c/keyring_get.c",
                        "pydatalib/c/keyring_service.c",
                    ],
                    include_dirs=["pydatalib/h"],
                    define_macros=[("_AE_BIMODAL", "1")],
                    library_dirs=["/usr/lib/"],
                    extra_compile_args=[
                        "-D_XOPEN_SOURCE_EXTENDED",
                        "-Wc,lp64,langlvl(EXTC99),STACKPROTECT(ALL),",
                        "-qcpluscmt",
                    ],
                )
            ],
            "cmdclass": {"built_ext": build_ext},
        }
    )
