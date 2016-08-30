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
from shortwave.messaging import SP, CRLF, MessageHeaderDict, header_names
from shortwave.numbers import HTTP_PORT
from shortwave.transmission import Transmitter, Connection
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


class HTTPTransmitter(Transmitter):

    def __init__(self, socket, headers):
        super(HTTPTransmitter, self).__init__(socket)
        self.headers = MessageHeaderDict(headers)

    def transmit(self, request):
        method = request.method
        target = request.target
        body = request.body
        headers = self.headers.copy()

        assert isinstance(method, bytes)
        assert isinstance(target, bytes)

        def transmit_(*data):
            log_data = b"".join(data).decode()
            for line in log_data.splitlines():
                log.info("T[%d]: %s", self.fd, line)
            super(HTTPTransmitter, self).transmit(*data)

        if callable(body):
            # A callable body signals that we want to send chunked data
            headers[b"Transfer-Encoding"] = b"chunked"
            headers.update(request.headers)
            transmit_(method, SP, target, SP, HTTP_VERSION, CRLF, headers.to_bytes(), CRLF)
            for chunk in body():
                if not isinstance(chunk, bytes):
                    chunk = bstr(chunk)
                chunk_size = len(chunk)
                if chunk_size:
                    transmit_("{:X}".format(chunk_size).encode("utf-8"), CRLF, chunk, CRLF)
            transmit_(b"0", CRLF, CRLF)

        else:
            # Otherwise, we'll just send fixed-length data
            if body is None:
                body = b""
            elif isinstance(body, dict):
                headers[b"Content-Type"] = b"application/json"
                body = json_dumps(body, separators=",:", ensure_ascii=True).encode("UTF-8")
            elif not isinstance(body, bytes):
                body = bstr(body)
            content_length = len(body)
            if content_length:
                content_length_bytes = bstr(content_length)
                headers[b"Content-Length"] = content_length_bytes
            headers.update(request.headers)
            transmit_(method, SP, target, SP, HTTP_VERSION, CRLF, headers.to_bytes(), CRLF, body)


class HTTP(Connection):
    Tx = HTTPTransmitter

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
        self.responses = deque()
        self.response_handler = self.on_status_line

    def exchange(self, request, response):
        self.responses.append(response)
        self.transmitter.transmit(request)
        return response

    def get(self, target, response=None, **headers):
        """ Make an asynchronous GET request to the remote host.
        """
        return self.exchange(HTTPRequest(b"GET", target, **headers),
                             response or HTTPResponse())

    def head(self, target, response=None, **headers):
        """ Make a HEAD request to the remote host.
        """
        return self.exchange(HTTPRequest(b"HEAD", target, **headers),
                             response or HTTPResponse())

    def post(self, target, body, response=None, **headers):
        """ Make a POST request to the remote host.
        """
        return self.exchange(HTTPRequest(b"POST", target, body, **headers),
                             response or HTTPResponse())

    def put(self, target, body, response=None, **headers):
        """ Make a PUT request to the remote host.
        """
        return self.exchange(HTTPRequest(b"PUT", target, body, **headers),
                             response or HTTPResponse())

    def delete(self, target, response=None, **headers):
        """ Make a DELETE request to the remote host.
        """
        return self.exchange(HTTPRequest(b"DELETE", target, **headers),
                             response or HTTPResponse())

    def connect(self, target, response=None, **headers):
        """ Make a CONNECT request to the remote host.
        """
        return self.exchange(HTTPRequest(b"CONNECT", target, **headers),
                             response or HTTPResponse())

    def options(self, target=b"*", response=None, **headers):
        """ Make an OPTIONS request to the remote host.
        """
        return self.exchange(HTTPRequest(b"OPTIONS", target, **headers),
                             response or HTTPResponse())

    def trace(self, target, response=None, **headers):
        """ Make a TRACE request to the remote host.
        """
        return self.exchange(HTTPRequest(b"TRACE", target, **headers),
                             response or HTTPResponse())

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
