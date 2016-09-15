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

from shortwave import Connection, line_limiter, countdown_limiter
from shortwave.compat import bstr
from shortwave.concurrency import synchronized
from shortwave.messaging import SP, CRLF, MessageHeaderDict, header_names, parse_header
from shortwave.numbers import HTTP_PORT, HTTPS_PORT
from shortwave.uri import parse_uri, parse_authority

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


crlf_limiter = line_limiter(b"\r\n")


class HTTPHeaderDict(MessageHeaderDict):

    def apply_authority(self, authority):
        user_info, address = parse_authority(authority, 2)
        if b"Host" not in self:
            self[b"Host"] = address
        if user_info and b"Authorization" not in self:
            self[b"Authorization"] = basic_auth(user_info)


class HTTP(Connection):

    default_port = HTTP_PORT
    secure = False

    def __init__(self, authority, receiver=None, **headers):
        super(HTTP, self).__init__(authority, secure=self.secure, receiver=receiver)
        self.limiter = crlf_limiter
        self.requests = deque()
        self.request_headers = HTTPHeaderDict(headers)
        self.request_headers.apply_authority(authority)
        self.responses = deque()
        self.response_handler = self.on_status_line

    def append(self, request, response):
        self.requests.append(request)
        self.responses.append(response)

    def transmit(self):

        data = []
        append = data.append
        requests = self.requests

        def transmit_():
            if data:
                log_data = b"".join(data).decode()
                for line in log_data.splitlines():
                    log.info("T[%d]: %s", self.fd, line)
                self.transmitter.transmit(*data)
                data[:] = []

        while requests:
            request = requests.popleft()

            method = request.method
            target = request.target
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
                headers.update(request.headers)
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
                self.limiter = crlf_limiter
                self.response_handler = self.on_status_line

    def on_status_line(self, response, data):
        log.info("R[%d]: %s", self.fd, data.decode())
        http_version, status_code, reason_phrase = data.split(SP, 2)
        response.http_version = bytes(http_version)
        response.status_code = int(status_code)
        response.reason_phrase = bytes(reason_phrase)
        response.headers = HTTPHeaderDict()
        self.response_handler = self.on_header_line
        return True

    def on_header_line(self, response, data):
        log.info("R[%d]: %s", self.fd, data.decode())
        if data:
            name, _, value = data.partition(b":")
            response.headers[name] = value.strip()
            return True
        if response.headers.get("transfer-encoding", b"").lower() == b"chunked":
            self.limiter = crlf_limiter
            self.response_handler = self.on_chunk_size
            return True
        self.limiter = countdown_limiter(int(response.headers.get("content-length", 0)))
        if self.limiter.remaining():
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
            return bool(self.limiter.remaining())

    def on_chunk_size(self, response, data):
        # TODO: parse chunk extensions <https://tools.ietf.org/html/rfc7230#section-4.1.1>
        chunk_size = int(data, 16)
        if chunk_size == 0:
            self.limiter = crlf_limiter
            self.response_handler = self.on_final_chunk_trailer
        else:
            self.limiter = countdown_limiter(chunk_size)
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
            if self.limiter.remaining() == 0:
                self.limiter = crlf_limiter
                self.response_handler = self.on_chunk_trailer
            return True

    def on_chunk_trailer(self, response, data):
        # TODO: parse chunk trailer <https://tools.ietf.org/html/rfc7230#section-4.1.2>
        self.response_handler = self.on_chunk_size
        return True

    def on_final_chunk_trailer(self, response, data):
        # TODO: parse chunk trailer <https://tools.ietf.org/html/rfc7230#section-4.1.2>
        return False


class HTTPS(HTTP):

    default_port = HTTPS_PORT
    secure = True


class HTTPRequest(object):

    @classmethod
    def get(cls, target, headers=None, **kwheaders):
        headers = HTTPHeaderDict(headers or {}, **kwheaders)
        scheme, authority, path_query, _ = parse_uri(target, 4)
        if authority:
            headers.apply_authority(authority)
        if scheme is None or scheme == b"http":
            return HTTPRequest(b"GET", path_query, headers=headers)
        else:
            raise ValueError("Unsupported scheme %r" % scheme)

    @classmethod
    def head(cls, target, headers=None, **kwheaders):
        headers = HTTPHeaderDict(headers or {}, **kwheaders)
        scheme, authority, path_query, _ = parse_uri(target, 4)
        if authority:
            headers.apply_authority(authority)
        if scheme is None or scheme == b"http":
            return HTTPRequest(b"HEAD", path_query, headers=headers)
        else:
            raise ValueError("Unsupported scheme %r" % scheme)

    @classmethod
    def post(cls, target, body, headers=None, **kwheaders):
        headers = HTTPHeaderDict(headers or {}, **kwheaders)
        scheme, authority, path_query, _ = parse_uri(target, 4)
        if authority:
            headers.apply_authority(authority)
        if scheme is None or scheme == b"http":
            return HTTPRequest(b"POST", path_query, body, headers=headers)
        else:
            raise ValueError("Unsupported scheme %r" % scheme)

    @classmethod
    def put(cls, target, body, headers=None, **kwheaders):
        headers = HTTPHeaderDict(headers or {}, **kwheaders)
        scheme, authority, path_query, _ = parse_uri(target, 4)
        if authority:
            headers.apply_authority(authority)
        if scheme is None or scheme == b"http":
            return HTTPRequest(b"PUT", path_query, body, headers=headers)
        else:
            raise ValueError("Unsupported scheme %r" % scheme)

    @classmethod
    def delete(cls, target, headers=None, **kwheaders):
        headers = HTTPHeaderDict(headers or {}, **kwheaders)
        scheme, authority, path_query, _ = parse_uri(target, 4)
        if authority:
            headers.apply_authority(authority)
        if scheme is None or scheme == b"http":
            return HTTPRequest(b"DELETE", path_query, headers=headers)
        else:
            raise ValueError("Unsupported scheme %r" % scheme)

    @classmethod
    def connect(cls, target, headers=None, **kwheaders):
        # TODO
        return HTTPRequest(b"CONNECT", target, headers, **kwheaders)

    @classmethod
    def options(cls, target=b"*", headers=None, **kwheaders):
        # TODO
        return HTTPRequest(b"OPTIONS", target, headers, **kwheaders)

    @classmethod
    def trace(cls, target, headers=None, **kwheaders):
        # TODO
        return HTTPRequest(b"TRACE", target, *headers, **kwheaders)

    def __init__(self, method, target, body=None, headers=None, **kwheaders):
        self.method = method
        self.target = target or b"/"
        self.body = body
        self.headers = HTTPHeaderDict(headers or {}, **kwheaders)


class HTTPResponse(object):

    http_version = None
    status_code = None
    reason_phrase = None
    headers = None
    body = None
    end = None

    _charset = None
    _content = None
    _content_type = None

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

    def on_body_data(self, data):
        if self.body is None:
            self.body = bytearray()
        self.body[len(self.body):] = data

    def _parse_content_type(self):
        try:
            content_type, params = parse_header(self.headers[b"Content-Type"])
        except KeyError:
            self._content_type = "application/octet-stream"
            self._charset = None
        else:
            self._content_type = content_type.decode("iso-8859-1")
            try:
                self._charset = params[b"charset"].decode("iso-8859-1")
            except KeyError:
                self._charset = None

    @property
    def content_type(self):
        if self._content_type is None:
            self._parse_content_type()
        return self._content_type

    @property
    def charset(self):
        if self._content_type is None:
            self._parse_content_type()
        return self._charset or "ISO-8859-1"

    @property
    def content(self):
        if self._content is None:
            self.end.wait()
            content_type = self.content_type
            charset = self.charset
            if content_type.startswith("text/"):
                self._content = self.body.decode(charset)
            elif content_type == "application/json":
                from json import loads as json_loads
                self._content = json_loads(self.body.decode(charset))
            else:
                self._content = self.body
        return self._content


def basic_auth(*args):
    return b"Basic " + b64encode(b":".join(map(bstr, args)))


def get(uri, headers=None, **kwheaders):
    scheme, authority, target, fragment = parse_uri(uri, 4)
    if scheme == b"http":
        http = HTTP
    else:
        raise ValueError("Unsupported scheme %r" % scheme)
    with http(authority) as client:
        request = HTTPRequest.get(target, headers, **kwheaders)
        response = HTTPResponse()
        client.append(request, response)
    return response
