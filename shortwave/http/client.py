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

from base64 import b64encode
from collections import deque
from json import dumps as json_dumps
from logging import getLogger
from threading import Event

from shortwave.compat import bstr
from shortwave.concurrency import synchronized
from shortwave.messaging import SP, CRLF, MessageHeaderDict, header_names
from shortwave.numbers import HTTP_PORT
from shortwave.transmission import Connection
from shortwave.uri import parse_authority

HTTP_VERSION = b"HTTP/1.1"

log = getLogger("shortwave.http")

connection_default = {
    b"HTTP/1.0": b"close",
    b"HTTP/1.1": b"keep-alive",
}

header_names.update({
    "accept": b"Accept",
    "accept_charset": b"Accept-Charset",
    "accept_datetime": b"Accept-Datetime",
    "accept_encoding": b"Accept-Encoding",
    "accept_language": b"Accept-Language",
    "authorization": b"Authorization",
    "cache_control": b"Cache-Control",
    "connection": b"Connection",
    "content_md5": b"Content-MD5",
    "content_type": b"Content-Type",
    "cookie": b"Cookie",
    "date": b"Date",
    "expect": b"Expect",
    "from": b"From",
    "if_match": b"If-Match",
    "if_modified_since": b"If-Modified-Since",
    "if_none_match": b"If-None-Match",
    "if_range": b"If-Range",
    "if_unmodified_since": b"If-Unmodified-Since",
    "max_forwards": b"Max-Forwards",
    "origin": b"Origin",
    "pragma": b"Pragma",
    "proxy_authorization": b"Proxy-Authorization",
    "range": b"Range",
    "referer": b"Referer",
    "te": b"TE",
    "user_agent": b"User-Agent",
    "upgrade": b"Upgrade",
    "via": b"Via",
    "warning": b"Warning",
})


class HTTP(Connection):

    def __init__(self, authority, receiver=None, rx_buffer_size=None, **headers):
        user_info, host, port = parse_authority(authority)
        if user_info:
            headers[b"Authorization"] = basic_auth(user_info)
        if port:
            headers[b"Host"] = host + b":" + bstr(port)
        else:
            headers[b"Host"] = host
        super(HTTP, self).__init__((host, port or HTTP_PORT), receiver, rx_buffer_size, headers)
        self.data_limit = b"\r\n"
        self.requests = deque()
        self.request_headers = MessageHeaderDict(headers)
        self.responses = deque()
        self.response_handler = self.on_status_line

    def append(self, request, response):
        self.requests.append(request)
        self.responses.append(response)

    def transmit(self):

        data = []
        append = data.append

        def transmit_():
            if data:
                log_data = b"".join(data).decode()
                for line in log_data.splitlines():
                    log.info("T[%d]: %s", self.fd, line)
                self.transmitter.transmit(*data)
                data[:] = []

        while self.requests:
            request = self.requests.popleft()

            method = request.method
            target = request.target  # TODO: if this is a full URI, parse it and use the host for the Host header
            body = request.body
            headers = self.request_headers.copy()

            assert isinstance(method, bytes)
            assert isinstance(target, bytes)

            append(method)
            append(SP)
            append(target)
            append(SP)
            append(HTTP_VERSION)
            append(CRLF)

            if body is None:
                append(headers.to_bytes())
                append(CRLF)

            elif callable(body):
                # A callable body signals that we want to send chunked data
                headers[b"Transfer-Encoding"] = b"chunked"
                headers.update(request.headers)
                append(headers.to_bytes())
                append(CRLF)
                transmit_()
                for chunk in body():
                    if not isinstance(chunk, bytes):
                        chunk = bstr(chunk)
                    chunk_size = len(chunk)
                    if chunk_size:
                        append("{:X}".format(chunk_size).encode("utf-8"))
                        append(CRLF)
                        append(chunk)
                        append(CRLF)
                        transmit_()
                append(b"0")
                append(CRLF)
                append(CRLF)
                transmit_()

            else:
                # Otherwise, we'll just send fixed-length data
                if isinstance(body, dict):
                    headers[b"Content-Type"] = b"application/json"
                    body = json_dumps(body, separators=",:", ensure_ascii=True).encode("UTF-8")
                elif not isinstance(body, bytes):
                    body = bstr(body)
                content_length = len(body)
                if content_length:
                    content_length_bytes = bstr(content_length)
                    headers[b"Content-Length"] = content_length_bytes
                headers.update(request.headers)
                append(headers.to_bytes())
                append(CRLF)
                append(body)

        transmit_()

    def sync(self):
        self.transmit()
        while self.responses:
            self.responses[0].end.wait()

    @synchronized
    def close(self):
        self.sync()
        super(HTTP, self).close()

    def on_data(self, data):
        response = self.responses[0]
        more = self.response_handler(response, data)
        if not more:
            log.debug("Marking %r as complete", response)
            response.end.set()
            self.responses.popleft()
            connection = response.headers.get(b"connection",
                                              connection_default[response.http_version])
            if connection.lower() == b"close":
                self.close()
            else:
                self.data_limit = b"\r\n"
                self.response_handler = self.on_status_line

    def on_status_line(self, response, data):
        log.info("R[%d]: %s", self.fd, data.decode())
        http_version, status_code, reason_phrase = data.split(SP, 2)
        response.http_version = bytes(http_version)
        response.status_code = int(status_code)
        response.reason_phrase = bytes(reason_phrase)
        response.headers = MessageHeaderDict()
        self.response_handler = self.on_header_line
        return True

    def on_header_line(self, response, data):
        log.info("R[%d]: %s", self.fd, data.decode())
        if data:
            name, _, value = data.partition(b":")
            response.headers[name] = value.strip()
            return True
        if response.headers.get("transfer-encoding", b"").lower() == b"chunked":
            self.data_limit = b"\r\n"
            self.response_handler = self.on_chunk_size
            return True
        self.data_limit = int(response.headers.get("content-length", 0))
        if self.data_limit:
            self.response_handler = self.on_body_data
            return True
        # TODO determine whether there is no content or whether content ends on close
        return False

    def on_body_data(self, response, data):
        if len(data) > 1024:
            log.info("R[%d]: %d bytes", self.fd, len(data))
        else:
            log.info("R[%d]: %r", self.fd, bytes(data))
        try:
            response.on_body_data(data)
        finally:
            self.data_limit -= len(data)
            return bool(self.data_limit)

    def on_chunk_size(self, response, data):
        # TODO: parse chunk extensions <https://tools.ietf.org/html/rfc7230#section-4.1.1>
        self.data_limit = chunk_size = int(data, 16)
        if chunk_size == 0:
            self.data_limit = b"\r\n"
            self.response_handler = self.on_final_chunk_trailer
        else:
            self.response_handler = self.on_chunk_data
        return True

    def on_chunk_data(self, response, data):
        if len(data) > 1024:
            log.info("R[%d]: %d bytes", self.fd, len(data))
        else:
            log.info("R[%d]: %r", self.fd, bytes(data))
        try:
            response.on_body_data(data)
        finally:
            self.data_limit -= len(data)
            if self.data_limit == 0:
                self.data_limit = b"\r\n"
                self.response_handler = self.on_chunk_trailer
            return True

    def on_chunk_trailer(self, response, data):
        # TODO: parse chunk trailer <https://tools.ietf.org/html/rfc7230#section-4.1.2>
        self.response_handler = self.on_chunk_size
        return True

    def on_final_chunk_trailer(self, response, data):
        # TODO: parse chunk trailer <https://tools.ietf.org/html/rfc7230#section-4.1.2>
        return False


class HTTPRequest(object):

    @classmethod
    def get(cls, target, **headers):
        return HTTPRequest(b"GET", target, **headers)

    @classmethod
    def head(cls, target, **headers):
        return HTTPRequest(b"HEAD", target, **headers)

    @classmethod
    def post(cls, target, body, **headers):
        return HTTPRequest(b"POST", target, body, **headers)

    @classmethod
    def put(cls, target, body, **headers):
        return HTTPRequest(b"PUT", target, body, **headers)

    @classmethod
    def delete(cls, target, **headers):
        return HTTPRequest(b"DELETE", target, **headers)

    @classmethod
    def connect(cls, target, **headers):
        return HTTPRequest(b"CONNECT", target, **headers)

    @classmethod
    def options(cls, target=b"*", **headers):
        return HTTPRequest(b"OPTIONS", target, **headers)

    @classmethod
    def trace(cls, target, **headers):
        return HTTPRequest(b"TRACE", target, **headers)

    def __init__(self, method, target, body=None, **headers):
        self.method = method
        self.target = target
        self.body = body
        self.headers = headers


class HTTPResponse(object):

    http_version = None
    status_code = None
    reason_phrase = None
    headers = None
    end = None

    def __new__(cls, *args, **kwargs):
        inst = object.__new__(cls)
        inst.end = Event()
        return inst

    def __repr__(self):
        return "<%s at 0x%x>" % (self.__class__.__name__, id(self))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __getitem__(self, name):
        return self.headers[name]

    def on_body_data(self, data):
        # TODO: buffer raw data and coerce to typed content for certain content types
        self.on_content(data)

    def on_content(self, data):
        pass


def basic_auth(*args):
    return b"Basic " + b64encode(b":".join(map(bstr, args)))
