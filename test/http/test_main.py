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

    def test_multiple_requests_for_same_authority(self):
        from shortwave.http.__main__ import get

        # Given
        out = BytesIO()

        # When
        get("shortwave.http", "get", "http://shortwave.tech/hello", "/hello", out=out)

        # Then
        assert out.getvalue() == b"hello, world\r\nhello, world\r\n"


class HeadMethodTestCase(TestCase):

    def test_hello(self):
        from shortwave.http.__main__ import head

        # Given
        out = BytesIO()

        # When
        head("shortwave.http", "head", "http://shortwave.tech/hello", out=out)

        # Then
        assert out.getvalue() == b""


class RestTestCase(TestCase):

    def test_get(self):
        from shortwave.http.__main__ import get
        from json import loads

        # Given
        out = BytesIO()

        # When
        get("shortwave.http", "get", "http://shortwave.tech/rest/thing/a", out=out)

        # Then
        data = loads(out.getvalue().decode("utf-8"))
        del data["request"]["time"]
        del data["thing"]["size"]
        assert data == {
            "request": {
                "method": "GET",
                "collection": "thing",
                "element": "a",
            },
            "thing": {
                "name": "a",
            },
        }

    def test_post(self):
        from shortwave.http.__main__ import post
        from json import loads

        # Given
        out = BytesIO()

        # When
        post("shortwave.http", "post", "http://shortwave.tech/rest/thing/", "test", out=out)

        # Then
        data = loads(out.getvalue().decode("utf-8"))
        del data["request"]["time"]
        print(data)
        assert data == {
            "request": {
                "method": "POST",
                "collection": "thing",
            },
        }

    def test_put(self):
        from shortwave.http.__main__ import put
        from json import loads

        # Given
        out = BytesIO()

        # When
        put("shortwave.http", "put", "http://shortwave.tech/rest/thing/a", "test", out=out)

        # Then
        data = loads(out.getvalue().decode("utf-8"))
        del data["request"]["time"]
        assert data == {
            "request": {
                "method": "PUT",
                "collection": "thing",
                "element": "a",
            },
        }

    def test_delete(self):
        from shortwave.http.__main__ import delete
        from json import loads

        # Given
        out = BytesIO()

        # When
        delete("shortwave.http", "delete", "http://shortwave.tech/rest/thing/a", out=out)

        # Then
        data = loads(out.getvalue().decode("utf-8"))
        del data["request"]["time"]
        assert data == {
            "request": {
                "method": "DELETE",
                "collection": "thing",
                "element": "a",
            },
        }
