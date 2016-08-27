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


class GetMethodTestCase(TestCase):

    def test_response_context_manager(self):
        from shortwave import http

        with http.get(b"http://shortwave.tech/hello") as response:
            assert response.status_code == 200
            assert response.read() == b"hello, world\r\n"

    def test_synchronous_get_function(self):
        from shortwave import http

        response = http.get(b"http://shortwave.tech/hello")
        assert response.http_version == b"HTTP/1.1"
        assert response.status_code == 200
        assert response.reason_phrase == b"OK"
        assert response.headers["Content-Type"].startswith(b"text/plain")
        assert response.content() == "hello, world\r\n"
        assert response.end.is_set()

    def test_asynchronous_get_method(self):
        from shortwave.http import HTTP

        http = HTTP(b"shortwave.tech")
        try:
            response = http.get(b"/hello").sync()
            assert response.http_version == b"HTTP/1.1"
            assert response.status_code == 200
            assert response.reason_phrase == b"OK"
            assert response.headers["Content-Type"].startswith(b"text/plain")
            assert response.content() == "hello, world\r\n"
            assert response.end.is_set()
        finally:
            http.close()


class JSONTestCase(TestCase):

    def test_can_get_json(self):
        from shortwave import http

        response = http.get(b"http://shortwave.tech/json?foo=bar")
        assert response.content() == {"method": "GET", "query": "foo=bar", "content": ""}

    def test_can_post_json(self):
        from shortwave import http

        response = http.post(b"http://shortwave.tech/json?foo=bar", b"bumblebee")
        assert response.content() == {"method": "POST", "query": "foo=bar", "content": "bumblebee"}

    def test_can_put_json(self):
        from shortwave import http

        response = http.put(b"http://shortwave.tech/json?foo=bar", b"bumblebee")
        assert response.content() == {"method": "PUT", "query": "foo=bar", "content": "bumblebee"}

    def test_can_delete_json(self):
        from shortwave import http

        response = http.delete(b"http://shortwave.tech/json?foo=bar")
        assert response.content() == {"method": "DELETE", "query": "foo=bar", "content": ""}

    def test_can_post_json_in_chunks(self):
        from shortwave.http import HTTP

        http = HTTP(b"shortwave.tech")

        def content():
            yield b"bum"
            yield b"ble"
            yield b"bee"

        try:
            response = http.post(b"/json?foo=bar", content).sync()
            assert response.content() == {"method": "POST", "query": "foo=bar",
                                          "content": "bumblebee"}
        finally:
            http.close()

    def test_can_post_dict_as_json(self):
        from shortwave.http import HTTP

        http = HTTP(b"shortwave.tech")
        try:
            response = http.post(b"/json?foo=bar", {"bee": "bumble"}).sync()
            assert response.content() == {"method": "POST", "query": "foo=bar",
                                          "content": '{"bee":"bumble"}'}
        finally:
            http.close()
