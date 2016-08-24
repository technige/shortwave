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
from shortwave.messaging import SP, CR_LF, HeaderDict, header_names, parse_header
from shortwave.numbers import HTTP_PORT
from shortwave.uri import parse_authority, parse_uri, build_uri
from shortwave.util.compat import bstr
from shortwave.util.concurrency import sync

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
        log.info("T[%d]: %s", self.fd, b"".join(data))
        super(HTTPTransmitter, self).transmit(*data)

    def request(self, method, uri, body=None, **headers):
        if not isinstance(method, bytes):
            method = bstr(method)

        if not isinstance(uri, bytes):
            uri = bstr(uri)

        transmit = self.transmit
        request_headers = self.headers.copy()

        if callable(body):
            # A callable body signals that we want to send chunked content
            request_headers[b"Transfer-Encoding"] = b"chunked"
            request_headers.update(headers)
            transmit(method, SP, uri, SP, HTTP_VERSION, CR_LF,
                     request_headers.to_bytes(), CR_LF)
            for chunk in body():
                if not isinstance(chunk, bytes):
                    chunk = bstr(chunk)
                chunk_size = len(chunk)
                if chunk_size:
                    transmit("{:X}".format(chunk_size).encode("utf-8"), CR_LF, chunk, CR_LF)
            transmit(b"0", CR_LF, CR_LF)

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
            transmit(method, SP, uri, SP, HTTP_VERSION, CR_LF,
                     request_headers.to_bytes(), CR_LF, body)


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

    def options(self, uri=b"*", response=None, **headers):
        """ Make an OPTIONS request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.request(b"OPTIONS", uri, **headers)
        return response

    def get(self, uri, response=None, **headers):
        """ Make an asynchronous GET request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.request(b"GET", uri, **headers)
        return response

    def head(self, uri, response=None, **headers):
        """ Make a HEAD request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.request(b"HEAD", uri, **headers)
        return response

    def post(self, uri, body, response=None, **headers):
        """ Make a POST request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.request(b"POST", uri, body, **headers)
        return response

    def put(self, uri, body, response=None, **headers):
        """ Make a PUT request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.request(b"PUT", uri, body, **headers)
        return response

    def patch(self, uri, body, response=None, **headers):
        """ Make a PATCH request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.request(b"PATCH", uri, body, **headers)
        return response

    def delete(self, uri, response=None, **headers):
        """ Make a DELETE request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.request(b"DELETE", uri, **headers)
        return response

    def trace(self, uri, response=None, **headers):
        """ Make a TRACE request to the remote host.
        """
        if response is None:
            response = HTTPResponse()
        self.responses.append(response)
        self.transmitter.request(b"TRACE", uri, **headers)
        return response

    def on_data(self, data):
        self.response_handler(self.responses[0], data)

    def on_status_line(self, response, data):
        log.info("R[%d]: %s", self.fd, data)
        http_version, status_code, reason_phrase = data.split(SP, 2)
        try:
            response.on_status_line(bytes(http_version), int(status_code), bytes(reason_phrase))
        finally:
            self.response_handler = self.on_headers

    def on_headers(self, response, data):
        if data:
            log.info("R[%d]: %s", self.fd, data)
            name, _, value = data.partition(b":")
            value = value.strip()
            try:
                response.on_header_line(name, value)
            finally:
                self.response_headers[name] = value
        else:
            self.data_limit = int(self.response_headers.get("content-length", 0))  # TODO: substitute with content-length (or chunking)
            if self.data_limit:
                self.response_handler = self.on_fixed_length_content
            else:
                self.on_complete(response)

    def on_fixed_length_content(self, response, data):
        if len(data) > 1024:
            log.info("R[%d]: b*%d", self.fd, len(data))
        else:
            log.info("R[%d]: %r", self.fd, data)
        try:
            response.on_content(data)
        finally:
            self.data_limit -= len(data)
            if self.data_limit == 0:
                self.on_complete(response)

    def on_complete(self, response):
        try:
            response.on_complete()
        finally:
            log.debug("Marking %r as complete", response)
            response.complete.set()
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
        self.body = bytearray()
        self.complete = Event()

    def __repr__(self):
        return "<%s at 0x%x>" % (self.__class__.__name__, id(self))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def sync(self, timeout=None):
        log.debug("Waiting for %r to complete", self)
        if self.complete.wait(timeout):
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

    def on_complete(self):
        pass


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
