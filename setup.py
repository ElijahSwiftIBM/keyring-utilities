# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['pydatalib', 'pydatalib.py']

package_data = \
{'': ['*'], 'pydatalib': ['c/*', 'h/*']}

install_requires = \
['defusedxml>=0.7.1']

setup_kwargs = {
    'name': 'pydatalib',
    'version': '0.1a1',
    'description': 'Python interface to Certificates using R_Datalib RACF Callable Service.',
    'long_description': 'None',
    'author': 'Elijah Swift',
    'author_email': 'elijah.swift@ibm.com',
    'maintainer': 'Elijah Swift',
    'maintainer_email': 'elijah.swift@ibm.com',
    'url': 'None',
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'python_requires': '>=3.10',
}
from build_extension import *
build(setup_kwargs)

setup(**setup_kwargs)
