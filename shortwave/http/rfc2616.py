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

from shortwave import Connection, Transmitter
from shortwave.messaging import SP, CR_LF, HeaderDict, header_names
from shortwave.numbers import HTTP_PORT
from shortwave.uri import parse_authority, parse_uri, build_uri
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

    def transmit(self, *data):
        log.info("T[%d]: [HTTP] %s", self.fd, b"".join(data))
        super(HTTPTransmitter, self).transmit(*data)

    def request(self, method, uri, body=None, **headers):
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


class HTTPResponse(object):

    state = None

    def __init__(self, connection):
        self.connection = connection
        self.fd = self.connection.socket.fileno()
        self.headers = HeaderDict()
        self.reset()

    def reset(self):
        self.headers.clear()
        self.connection.limit = b"\r\n"
        self.state = self.receiving_status_line

    def append(self, data):
        self.state(data)

    def receiving_status_line(self, data):
        log.info("R[%d]: [HTTP] %s", self.fd, data)
        http_version, status_code, reason_phrase = data.split(SP, 2)
        self.connection.on_status_line(http_version, int(status_code), reason_phrase)
        self.state = self.receiving_headers

    def receiving_headers(self, data):
        if data:
            log.info("R[%d]: [HTTP] %s", self.fd, data)
            name, _, value = data.partition(b":")
            value = value.strip()
            self.connection.on_header(name, value)
            self.headers[name] = value
        else:
            self.connection.limit = int(self.headers["content-length"])  # TODO: substitute with content-length (or chunking)
            self.state = self.receiving_fixed_length_body

    def receiving_fixed_length_body(self, data):
        log.info("R[%d]: [HTTP] b*%d", self.fd, len(data))
        self.connection.on_body(data)
        self.connection.limit -= len(data)
        if self.connection.limit == 0:
            self.connection.on_end()
            if self.headers.get("connection", "").lower() == "close":
                self.connection.close()
            else:
                self.reset()


class HTTP(Connection):
    Tx = HTTPTransmitter

    def __init__(self, authority):
        user_info, host, port = parse_authority(authority)
        headers = {}
        if user_info:
            headers[b"Authorization"] = basic_auth(user_info)
        if port:
            headers[b"Host"] = host + b":" + bstr(port)
        else:
            headers[b"Host"] = host
        super(HTTP, self).__init__((host, port or HTTP_PORT), headers)
        self.response = HTTPResponse(self)

    def options(self, uri=b"*", **headers):
        """ Make an OPTIONS request to the remote host.
        """
        return self.transmitter.request(b"OPTIONS", uri, **headers)

    def get(self, uri, **headers):
        """ Make a GET request to the remote host.
        """
        return self.transmitter.request(b"GET", uri, **headers)

    def head(self, uri, **headers):
        """ Make a HEAD request to the remote host.
        """
        return self.transmitter.request(b"HEAD", uri, **headers)

    def post(self, uri, body, **headers):
        """ Make a POST request to the remote host.
        """
        return self.transmitter.request(b"POST", uri, body, **headers)

    def put(self, uri, body, **headers):
        """ Make a PUT request to the remote host.
        """
        return self.transmitter.request(b"PUT", uri, body, **headers)

    def patch(self, uri, body, **headers):
        """ Make a PATCH request to the remote host.
        """
        return self.transmitter.request(b"PATCH", uri, body, **headers)

    def delete(self, uri, **headers):
        """ Make a DELETE request to the remote host.
        """
        return self.transmitter.request(b"DELETE", uri, **headers)

    def trace(self, uri, **headers):
        """ Make a TRACE request to the remote host.
        """
        return self.transmitter.request(b"TRACE", uri, **headers)

    def on_data(self, data):
        self.response.append(data)

    def on_status_line(self, http_version, status_code, reason_phrase):
        pass

    def on_header(self, name, value):
        pass

    def on_body(self, data):
        pass

    def on_end(self):
        pass


def basic_auth(*args):
    return b"Basic " + b64encode(b":".join(map(bstr, args)))


def get(uri, **headers):
    """ Make a GET request to a URI.
    """
    scheme, authority, path, query, fragment = parse_uri(uri)
    http = HTTP(authority)
    try:
        return http.get(uri, **headers)
    finally:
        http.stop_tx()


def post(uri, body, **headers):
    """ Make a POST request to a URI.
    """
    scheme, authority, path, query, fragment = parse_uri(uri)
    ref_uri = build_uri(path=path, query=query, fragment=fragment)
    http = HTTP(authority)
    try:
        return http.post(ref_uri, body, connection="close", **headers)
    finally:
        http.stop_tx()
