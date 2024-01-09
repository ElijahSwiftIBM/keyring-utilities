"""Build R_Datalib (pykeyring) Python extesion."""

import os

from setuptools import Extension, setup


def main():
    """Python extension build entrypoint."""
    os.environ["_CC_CCMODE"] = "1"
    os.environ["_CXX_CCMODE"] = "1"
    os.environ["_C89_CCMODE"] = "1"
    os.environ["_CC_EXTRA_ARGS"] = "1"
    os.environ["_CXX_EXTRA_ARGS"] = "1"
    os.environ["_C89_EXTRA_ARGS"] = "1"
    os.environ["CC"] = "xlc"
    os.environ["CXX"] = "xlc++"
    setup_args = {
            "ext_modules": [
                Extension(
                    "pykeyring",
                    sources = [
                        "keyring_py.c",
                        "src/c/keyring_get.c",
                        "src/c/keyring_service.c"
                    ],
                    include_dirs = ['src/h'],
                    define_macros = [("_AE_BIMODAL", "1")],
                    libraries = ["GSKCMS64.x"],
                    library_dirs = ["/usr/lib/"],
                    extra_compile_args=[
                        "-D_XOPEN_SOURCE_EXTENDED",
                        "-Wc,lp64,langlvl(EXTC99),STACKPROTECT(ALL),",
                        "-qcpluscmt",
                    ],
                )
            ],
    }
    setup(**setup_args)

if __name__ == "__main__":
    main()