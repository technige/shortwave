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

from __future__ import print_function

from argparse import ArgumentParser
from logging import INFO, DEBUG
from os import write as os_write
from sys import argv, stdin, stdout

from shortwave.http import HTTP, HTTPS, HTTPResponse, HTTPRequest, basic_auth
from shortwave.uri import parse_uri
from shortwave.watcher import watch


class ResponseWriter(HTTPResponse):

    def __init__(self, out):
        self.out = out
        try:
            fd = out.fileno()
        except IOError:
            def write(b):
                out.write(b)
        else:
            def write(b):
                os_write(fd, b)
        self.write = write

    def on_body_data(self, data):
        self.write(data)


def usage():
    print("usage: shortwave.http get <uri> [<uri> ...]")
    print("       shortwave.http head <uri> [<uri> ...]")
    print("       shortwave.http post <uri> <body>")
    print("       shortwave.http put <uri> <body>")
    print("       shortwave.http delete <uri>")


def safe_request(prog, method, *args, encoding="UTF-8", out=stdout):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri [uri ...]".format(method))
    parser.add_argument("-1", "--single-receiver", action="store_true")
    parser.add_argument("-p", "--password")
    parser.add_argument("-s", "--secure", action="store_true")
    parser.add_argument("-u", "--user")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri", nargs="+")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave.http", level=INFO)
    if parsed.very_verbose:
        watch("shortwave.transmission", level=DEBUG)
    if parsed.single_receiver:
        receiver = HTTP.Rx()
        receiver.start()
    else:
        receiver = None

    headers = {}
    if parsed.user or parsed.password:
        headers[b"Authorization"] = basic_auth(parsed.user, parsed.password)
    clients = []
    responses = []
    http = HTTPS if parsed.secure else HTTP
    client = None
    try:
        for uri in parsed.uri:
            scheme, authority, target, fragment = parse_uri(uri.encode(encoding), 4)
            if scheme is not None:
                if scheme == b"http":
                    http = HTTP
                elif scheme == b"https":
                    http = HTTPS
                else:
                    raise ValueError("Unsupported URI scheme: %r" % scheme)
            if client is None and not authority:
                authority = b"127.0.0.1"
            if authority:
                client = http(authority, receiver=receiver)
                clients.append(client)
            response = HTTPResponse()
            responses.append(response)
            client.append(getattr(HTTPRequest, method)(target, **headers), response)
        for client in clients:
            client.transmit()
        for response in responses:
            print(response.content, end="", file=out)
    finally:
        for client in clients:
            client.close()
        if receiver:
            receiver.stop()


def post(prog, method, *args, encoding="UTF-8", out=stdout):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri body".format(method))
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri")
    parser.add_argument("body")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave.http", level=INFO)
    if parsed.very_verbose:
        watch("shortwave.transmission", level=DEBUG)

    scheme, authority, target, fragment = parse_uri(parsed.uri.encode(encoding), 4)
    http = HTTP(authority, connection="close")
    headers = {}
    if parsed.json:
        headers["content_type"] = b"application/json"
    try:
        http.append(HTTPRequest.post(target, parsed.body, **headers), ResponseWriter(out))
    finally:
        http.close()


def put(prog, method, *args, encoding="UTF-8", out=stdout):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri body".format(method))
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri")
    parser.add_argument("body")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave.http", level=INFO)
    if parsed.very_verbose:
        watch("shortwave.transmission", level=DEBUG)

    scheme, authority, target, fragment = parse_uri(parsed.uri.encode(encoding), 4)
    http = HTTP(authority, connection="close")
    headers = {}
    if parsed.json:
        headers["content_type"] = b"application/json"
    try:
        http.append(HTTPRequest.put(target, parsed.body, **headers), ResponseWriter(out))
    finally:
        http.close()


def delete(prog, method, *args, encoding="UTF-8", out=stdout):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri".format(method))
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave.http", level=INFO)
    if parsed.very_verbose:
        watch("shortwave.transmission", level=DEBUG)

    scheme, authority, target, fragment = parse_uri(parsed.uri.encode(encoding), 4)
    http = HTTP(authority, connection="close")
    headers = {}
    try:
        http.append(HTTPRequest.delete(target, **headers), ResponseWriter(out))
    finally:
        http.close()


get = safe_request
head = safe_request


def main():
    argv[0] = "sw.http"
    if len(argv) == 1 or argv[1] == "help":
        usage()
    elif argv[1] == "get":
        get(*argv, encoding=stdin.encoding, out=stdout)
    elif argv[1] == "head":
        head(*argv, encoding=stdin.encoding, out=stdout)
    elif argv[1] == "post":
        post(*argv, encoding=stdin.encoding, out=stdout)
    elif argv[1] == "put":
        put(*argv, encoding=stdin.encoding, out=stdout)
    elif argv[1] == "delete":
        delete(*argv, encoding=stdin.encoding, out=stdout)
    else:
        usage()


if __name__ == "__main__":
    main()
