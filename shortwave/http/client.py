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
from json import dumps as json_dumps, loads as json_loads
from logging import getLogger
from threading import Event

from shortwave import Connection, Transmitter
from shortwave.compat import bstr
from shortwave.messaging import SP, CRLF, HeaderDict, header_names, parse_header
from shortwave.numbers import HTTP_PORT
from shortwave.uri import parse_authority, parse_uri, build_uri

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
        self.headers = HeaderDict(headers)

    def transmit(self, *data):
        log_data = b"".join(data).decode()
        for line in log_data.splitlines():
            log.info("T[%d]: %s", self.fd, line)
        super(HTTPTransmitter, self).transmit(*data)

    def transmit_request(self, method, target, body=None, **headers):
        if not isinstance(method, bytes):
            method = bstr(method)

        if not isinstance(target, bytes):
            target = bstr(target)

        transmit = self.transmit
        request_headers = self.headers.copy()

        if callable(body):
            # A callable body signals that we want to send chunked content
            request_headers[b"Transfer-Encoding"] = b"chunked"
            request_headers.update(headers)
            transmit(method, SP, target, SP, HTTP_VERSION, CRLF, request_headers.to_bytes(), CRLF)
            for chunk in body():
                if not isinstance(chunk, bytes):
                    chunk = bstr(chunk)
                chunk_size = len(chunk)
                if chunk_size:
                    transmit("{:X}".format(chunk_size).encode("utf-8"), CRLF, chunk, CRLF)
            transmit(b"0", CRLF, CRLF)

        else:
            # Fixed-length content
            if body is None:
                body = b""
            elif isinstance(body, dict):
                request_headers[b"Content-Type"] = b"application/json"
                body = json_dumps(body, separators=",:", ensure_ascii=True).encode("UTF-8")
            elif not isinstance(body, bytes):
                body = bstr(body)
            content_length = len(body)
            if content_length:
                content_length_bytes = bstr(content_length)
                request_headers[b"Content-Length"] = content_length_bytes
            request_headers.update(headers)
            transmit(method, SP, target, SP, HTTP_VERSION, CRLF,
                     request_headers.to_bytes(), CRLF, body)


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
        self.response_headers = HeaderDict()

    def get(self, target, response=None, **headers):
        """ Make an asynchronous GET request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.transmit_request(b"GET", target, **headers)
        return response

    def head(self, target, response=None, **headers):
        """ Make a HEAD request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.transmit_request(b"HEAD", target, **headers)
        return response

    def post(self, target, body, response=None, **headers):
        """ Make a POST request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.transmit_request(b"POST", target, body, **headers)
        return response

    def put(self, target, body, response=None, **headers):
        """ Make a PUT request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.transmit_request(b"PUT", target, body, **headers)
        return response

    def delete(self, target, response=None, **headers):
        """ Make a DELETE request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.transmit_request(b"DELETE", target, **headers)
        return response

    def connect(self, target, response=None, **headers):
        """ Make a CONNECT request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.transmit_request(b"CONNECT", target, **headers)
        return response

    def options(self, target=b"*", response=None, **headers):
        """ Make an OPTIONS request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.transmit_request(b"OPTIONS", target, **headers)
        return response

    def trace(self, target, response=None, **headers):
        """ Make a TRACE request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.transmit_request(b"TRACE", target, **headers)
        return response

    def on_data(self, data):
        self.response_handler(self.responses[0], data)

    def on_status_line(self, response, data):
        log.info("R[%d]: %s", self.fd, data.decode())
        http_version, status_code, reason_phrase = data.split(SP, 2)
        try:
            response.on_status_line(bytes(http_version), int(status_code), bytes(reason_phrase))
        finally:
            self.response_handler = self.on_headers

    def on_headers(self, response, data):
        log.info("R[%d]: %s", self.fd, data.decode())
        if data:
            name, _, value = data.partition(b":")
            value = value.strip()
            try:
                response.on_header_line(name, value)
            finally:
                self.response_headers[name] = value
        else:
            if self.response_headers.get("transfer-encoding", b"").lower() == b"chunked":
                self.data_limit = b"\r\n"
                self.response_handler = self.on_chunk_size
            else:
                self.data_limit = int(self.response_headers.get("content-length", 0))
                if self.data_limit:
                    self.response_handler = self.on_fixed_length_content
                else:
                    # TODO determine whether there is no content or whether content ends on close
                    self.on_complete(response)

    def on_chunk_size(self, response, data):
        self.data_limit = response.chunk_size = int(data, 16)
        # TODO: parse chunk extensions <https://tools.ietf.org/html/rfc7230#section-4.1.1>
        self.response_handler = self.on_chunk_data

    def on_chunk_data(self, response, data):
        if len(data) > 1024:
            log.info("R[%d]: %d bytes", self.fd, len(data))
        else:
            log.info("R[%d]: %r", self.fd, bytes(data))
        try:
            response.on_content(data)
        finally:
            self.data_limit -= len(data)
            if self.data_limit == 0:
                self.data_limit = b"\r\n"
                self.response_handler = self.on_chunk_trailer

    def on_chunk_trailer(self, response, data):
        # TODO: parse chunk trailer <https://tools.ietf.org/html/rfc7230#section-4.1.2>
        if response.chunk_size == 0:
            self.on_complete(response)
        else:
            self.response_handler = self.on_chunk_size

    def on_fixed_length_content(self, response, data):
        if len(data) > 1024:
            log.info("R[%d]: %d bytes", self.fd, len(data))
        else:
            log.info("R[%d]: %r", self.fd, bytes(data))
        try:
            response.on_content(data)
        finally:
            self.data_limit -= len(data)
            if self.data_limit == 0:
                self.on_complete(response)

    def on_complete(self, response):
        log.debug("Marking %r as complete", response)
        try:
            response.end.set()
        finally:
            self.responses.popleft()
            headers = self.response_headers
            connection = headers.get(b"connection", connection_default[response.http_version])
            if connection.lower() == b"close":
                self.close()
            else:
                self.data_limit = b"\r\n"
                self.response_handler = self.on_status_line
                headers.clear()


class HTTPResponse(object):

    def __init__(self):
        self.http_version = None
        self.status_code = None
        self.reason_phrase = None
        self.headers = HeaderDict()
        self.chunk_size = None
        self.body = bytearray()
        self.end = Event()

    def __repr__(self):
        return "<%s at 0x%x>" % (self.__class__.__name__, id(self))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def sync(self, timeout=None):
        log.debug("Waiting for %r to complete", self)
        # TODO: handle keyboard interruption
        if self.end.wait(timeout):
            return self
        else:
            return None

    def content(self):
        """ Return typed content (type can vary)
        """
        self.sync()
        try:
            content_type, content_type_parameters = parse_header(self.headers[b"Content-Type"])
        except KeyError:
            pass
        else:
            content_type = content_type.decode("ISO-8859-1")
            encoding = content_type_parameters.get(b"charset", b"ISO-8859-1").decode("ISO-8859-1")
            if content_type.startswith("text/"):
                return self.body.decode(encoding)
            elif content_type == "application/json":
                return json_loads(self.body.decode(encoding))
            else:
                return self.body

    def read(self):
        """ Returns raw content
        """
        # TODO: proper reading
        self.sync()
        return self.body

    def on_status_line(self, http_version, status_code, reason_phrase):
        self.http_version = http_version
        self.status_code = status_code
        self.reason_phrase = reason_phrase

    def on_header_line(self, name, value):
        self.headers[name] = value

    def on_content(self, data):
        self.body[len(self.body):] = data


def basic_auth(*args):
    return b"Basic " + b64encode(b":".join(map(bstr, args)))


def get(uri, response=None, **headers):
    """ Make a synchronous GET request to a URI.
    """
    scheme, authority, path, query, fragment = parse_uri(uri)
    ref_uri = build_uri(path=path, query=query, fragment=fragment)
    http = HTTP(authority, connection="close")
    try:
        return http.get(ref_uri, response, **headers).sync()
    finally:
        http.close()


def post(uri, body, response=None, **headers):
    """ Make a synchronous POST request to a URI.
    """
    scheme, authority, path, query, fragment = parse_uri(uri)
    ref_uri = build_uri(path=path, query=query, fragment=fragment)
    http = HTTP(authority, connection="close")
    try:
        return http.post(ref_uri, body, response, **headers).sync()
    finally:
        http.close()


def put(uri, body, response=None, **headers):
    """ Make a synchronous PUT request to a URI.
    """
    scheme, authority, path, query, fragment = parse_uri(uri)
    ref_uri = build_uri(path=path, query=query, fragment=fragment)
    http = HTTP(authority, connection="close")
    try:
        return http.put(ref_uri, body, response, **headers).sync()
    finally:
        http.close()


def delete(uri, response=None, **headers):
    """ Make a synchronous DELETE request to a URI.
    """
    scheme, authority, path, query, fragment = parse_uri(uri)
    ref_uri = build_uri(path=path, query=query, fragment=fragment)
    http = HTTP(authority, connection="close")
    try:
        return http.delete(ref_uri, response, **headers).sync()
    finally:
        http.close()
