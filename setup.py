#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import os
from setuptools import setup


setup(
    name="Auth0-ci",
    version="1.0.5",
    author="Guillaume Destuynder",
    author_email="gdestuynder@mozilla.com",
    py_modules=["uploader_login_page", "uploader_rules", "uploader_clients"],
    description=("Super simple CI scripts for Auth0"),
    license="MPL",
    keywords="auth0 ci deploy",
    url="https://github.com/mozilla-iam/auth0-ci",
    install_requires=['authzerolib'],
    scripts=['uploader_clients.py', 'uploader_rules.py', 'uploader_login_page.py'],
    classifiers=["Development Status :: 5 - Production/Stable",
                 "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)"]
)
