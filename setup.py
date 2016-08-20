#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# Copyright 2011-2016, Nigel Small
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

from shortwave import __author__, __email__, __license__, __package__, __version__


packages = find_packages(exclude=("demo", "demo.*", "test", "test.*"))
package_metadata = {
    "name": __package__,
    "version": __version__,
    "description": "Library of networking components",
    "long_description": "Shortwave is a library of components for Python network applications.",
    "author": __author__,
    "author_email": __email__,
    "url": "http://shortwave.fm/",
    "entry_points": {
        "console_scripts": [
        ],
    },
    "packages": packages,
    "license": __license__,
    "classifiers": [
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Topic :: Internet",
        "Topic :: Software Development",
        "Topic :: Utilities",
    ],
    "zip_safe": False,
}

setup(**package_metadata)
