#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
"""Module for extracting test data from the test data folder"""

from __future__ import absolute_import, division, print_function, unicode_literals

import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)


REPLY_DATA = re.compile(r"<reply>\s*<data>(.*?)</data>", re.MULTILINE | re.DOTALL)


class TestData(object):
    """Class for extracting test data from the curl test data folder"""

    def __init__(self, data_folder: Path) -> None:
        """Create a TestData object"""
        self.data_folder = data_folder

    def get_test_data(self, test_number: int) -> str:
        """Get the test data for a given test number"""
        # Create the test file name
        filename = self.data_folder / f"test{test_number}"

        log.debug("Parsing file %s", filename)

        with open(filename, "r", encoding="utf-8") as f:
            contents = f.read()

        m = REPLY_DATA.search(contents)
        if not m:
            raise ValueError("Couldn't find a <reply><data> section")

        # Left-strip the data so we don't get a newline before our data.
        return m.group(1).lstrip()
