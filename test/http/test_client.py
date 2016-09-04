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

from shortwave.http.client import HTTPRequest


class HTTPRequestTestCase(TestCase):

    def test_get_origin_form_target(self):
        request = HTTPRequest.get(b"/hello")
        assert request.method == b"GET"
        assert request.target == b"/hello"
        assert not request.body
        assert not request.headers

    def test_get_absolute_form_target(self):
        request = HTTPRequest.get(b"http://shortwave.tech/hello")
        assert request.method == b"GET"
        assert request.target == b"/hello"
        assert not request.body
        assert len(request.headers) == 1
        assert request.headers[b"Host"] == b"shortwave.tech"

    def test_get_absolute_form_target_with_explicit_host_header(self):
        request = HTTPRequest.get(b"http://shortwave.tech/hello", host="shortwave.fm")
        assert request.method == b"GET"
        assert request.target == b"/hello"
        assert not request.body
        assert len(request.headers) == 1
        assert request.headers[b"Host"] == b"shortwave.fm"
