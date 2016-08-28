#!/usr/bin/env python
# coding: utf-8

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

from io import BytesIO
from unittest import TestCase


class GetMethodTestCase(TestCase):

    def test_hello(self):
        from shortwave.http.__main__ import get

        # Given
        out = BytesIO()

        # When
        get("shortwave.http", "get", "http://shortwave.tech/hello", out=out)

        # Then
        assert out.getvalue() == b"hello, world\r\n"


class HeadMethodTestCase(TestCase):

    def test_hello(self):
        from shortwave.http.__main__ import head

        # Given
        out = BytesIO()

        # When
        head("shortwave.http", "head", "http://shortwave.tech/hello", out=out)

        # Then
        assert out.getvalue() == b""
