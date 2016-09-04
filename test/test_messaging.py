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


from unittest import TestCase

from shortwave.messaging import MessageHeaderDict


class MessageHeaderDictTestCase(TestCase):

    def test_can_set_and_get_headers(self):
        headers = MessageHeaderDict()
        headers[b"Host"] = b"www.example.com"
        assert headers[b"Host"] == b"www.example.com"

    def test_can_set_unicode_headers(self):
        headers = MessageHeaderDict()
        headers[b"Host"] = u"www.example.com"
        assert headers[b"Host"] == b"www.example.com"

    def test_can_set_numeric_headers(self):
        headers = MessageHeaderDict()
        headers[b"Content-Length"] = 123
        assert headers[b"Content-Length"] == b"123"

    def test_can_only_set_one_of_each_key(self):
        headers = MessageHeaderDict()
        headers[b"Host"] = b"www.example.com"
        headers[b"Host"] = b"www.example.net"
        assert headers[b"Host"] == b"www.example.net"

    def test_key_case_is_normalised(self):
        headers = MessageHeaderDict()
        headers[b"Host"] = b"www.example.com"
        headers[b"host"] = b"www.example.net"
        assert headers[b"Host"] == b"www.example.net"

    def test_can_convert_to_dict(self):
        headers = MessageHeaderDict()
        headers[b"Host"] = b"www.example.com"
        headers[b"Content-Length"] = 123
        d = dict(headers)
        assert d == {b"Host": b"www.example.com", b"Content-Length": b"123"}

    def test_can_initialise_from_dict(self):
        headers = MessageHeaderDict({b"Host": b"www.example.com", b"Content-Length": b"123"})
        assert headers[b"Host"] == b"www.example.com"
        assert headers[b"Content-Length"] == b"123"

    def test_can_initialise_from_kwargs(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        assert headers[b"Host"] == b"www.example.com"
        assert headers[b"Content-Length"] == b"123"

    def test_can_initialise_from_kwargs_with_non_bytes_values(self):
        headers = MessageHeaderDict(host=u"www.example.com", content_length=123)
        assert headers[b"Host"] == b"www.example.com"
        assert headers[b"Content-Length"] == b"123"

    def test_can_delete_fields(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        del headers[b"Content-Length"]
        d = dict(headers)
        assert d == {b"Host": b"www.example.com"}

    def test_can_get_with_default(self):
        headers = MessageHeaderDict()
        value = headers.get(b"Host", b"www.example.com")
        assert value == b"www.example.com"

    def test_can_get_with_default_default(self):
        headers = MessageHeaderDict()
        value = headers.get(b"Host")
        assert value is None

    def test_can_copy(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        copy_of_headers = headers.copy()
        d = dict(copy_of_headers)
        assert d == {b"Host": b"www.example.com", b"Content-Length": b"123"}

    def test_can_initialise_from_header_dict(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        copy_of_headers = MessageHeaderDict(headers)
        d = dict(copy_of_headers)
        assert d == {b"Host": b"www.example.com", b"Content-Length": b"123"}

    def test_length(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        assert len(headers) == 2

    def test_contains(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        assert b"Host" in headers

    def test_does_not_contain(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        assert b"Transfer-Encoding" not in headers

    def test_can_iterate_keys(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        keys = set(headers.keys())
        assert keys == {b"Host", b"Content-Length"}

    def test_can_iterate_values(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        values = set(headers.values())
        assert values == {b"www.example.com", b"123"}

    def test_can_iterate_items(self):
        headers = MessageHeaderDict(host=b"www.example.com", content_length=b"123")
        items = set(headers.items())
        assert items == {(b"Host", b"www.example.com"), (b"Content-Length", b"123")}

    def test_repr(self):
        headers = MessageHeaderDict(host=b"www.example.com")
        assert repr(headers) == "Host: www.example.com\r\n"
