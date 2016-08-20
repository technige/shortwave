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
from json import dumps as json_dumps
from logging import getLogger

from shortwave import Protocol, Transmitter
from shortwave.messaging import SP, CR_LF, HeaderDict, header_names, Buffer
from shortwave.uri import parse_uri_authority, parse_uri
from shortwave.util.compat import bstr, jsonable

HTTP_VERSION = b"HTTP/1.1"

log = getLogger("shortwave")

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

    def request(self, method, uri, body=None, **headers):
        transmit = super(HTTPTransmitter, self).transmit
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
                    transmit(b"%X" % chunk_size, CR_LF, chunk, CR_LF)
            transmit(b"0", CR_LF, CR_LF)

        else:
            # Fixed-length content
            if isinstance(body, jsonable):
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


class HTTP(Protocol):
    Tx = HTTPTransmitter

    default_port = 80

    def __init__(self, authority):
        user_info, host, port = parse_uri_authority(authority)
        headers = {}
        if user_info:
            headers[b"Authorization"] = basic_auth(user_info)
        if port:
            headers[b"Host"] = host + b":" + bstr(port)
        else:
            headers[b"Host"] = host
        super(HTTP, self).__init__((host, port) or self.default_port, headers)
        self.response_state = 0
        self.buffer = Buffer()

    def request(self, method, uri, body=None, **headers):
        self.transmitter.request(method, uri, body, **headers)

    def options(self, uri=b"*", body=None, **headers):
        """ Make an OPTIONS request to the remote host.
        """
        return self.request(b"OPTIONS", uri, body, **headers)

    def get(self, uri, **headers):
        """ Make a GET request to the remote host.
        """
        return self.request(b"GET", uri, **headers)

    def head(self, uri, **headers):
        """ Make a HEAD request to the remote host.
        """
        return self.request(b"HEAD", uri, **headers)

    def post(self, uri, body=None, **headers):
        """ Make a POST request to the remote host.
        """
        return self.request(b"POST", uri, body, **headers)

    def put(self, uri, body=None, **headers):
        """ Make a PUT request to the remote host.
        """
        return self.request(b"PUT", uri, body, **headers)

    def patch(self, uri, body=None, **headers):
        """ Make a PATCH request to the remote host.
        """
        return self.request(b"PATCH", uri, body, **headers)

    def delete(self, uri, **headers):
        """ Make a DELETE request to the remote host.
        """
        return self.request(b"DELETE", uri, **headers)

    def trace(self, uri, body=None, **headers):
        """ Make a TRACE request to the remote host.
        """
        return self.request(b"TRACE", uri, body, **headers)

    def on_receive(self, view):
        self.buffer.write(view.tobytes())
        while self.buffer:
            if self.response_state == 0:
                line = self.buffer.read_line()
                if line is None:
                    break
                http_version, status_code, reason_phrase = line.split(SP, 2)
                self.on_status_line(http_version, int(status_code), reason_phrase)
                self.response_state = 1
            elif self.response_state == 1:
                line = self.buffer.read_line()
                if line is None:
                    break
                if line == b"":
                    self.response_state = 2
                else:
                    name, _, value = line.partition(b":")
                    self.on_header_line(name, value.lstrip())
            else:
                from sys import stdout
                stdout.write(self.buffer.read().decode("ISO-8859-1"))

    def on_status_line(self, http_version, status_code, reason_phrase):
        log.info("[HTTP] Rx: HTTP Version: %s", http_version)
        log.info("[HTTP] Rx: Status Code: %d", status_code)
        log.info("[HTTP] Rx: Reason Phrase: %s", reason_phrase)

    def on_header_line(self, name, value):
        log.info("[HTTP] Rx: %s: %s", name, value)


def basic_auth(*args):
    return b"Basic " + b64encode(b":".join(map(bstr, args)))


def get(uri, **headers):
    """ Make a GET request to a URI.
    """
    scheme, authority, path, query, fragment = parse_uri(uri)
    http = HTTP(authority)
    try:
        return http.request(b"GET", uri, **headers)
    finally:
        http.finish()
