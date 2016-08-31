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

from argparse import ArgumentParser
from logging import INFO, DEBUG
from os import write as os_write
from sys import argv, stdin, stdout

from shortwave.http import HTTP, HTTPResponse, HTTPRequest
from shortwave.uri import parse_uri, build_uri
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


def safe_request(prog, method, *args, arg_encoding="UTF-8", out=stdout):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri [uri ...]".format(method))
    parser.add_argument("-1", "--single-receiver", action="store_true")
    parser.add_argument("-r", "--rx-buffer-size", metavar="SIZE", default=4194304)
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

    connections = []
    responses = []
    http = None
    try:
        for uri in parsed.uri:
            scheme, authority, path, query, fragment = parse_uri(uri.encode(arg_encoding))
            if scheme and scheme != b"http":
                raise ValueError("Non-HTTP URI: %r" % uri)
            if authority:
                http = HTTP(authority, receiver, rx_buffer_size=parsed.rx_buffer_size)
                connections.append(http)
            target = build_uri(path=path, query=query, fragment=fragment)
            response = ResponseWriter(out)
            responses.append(response)
            http.append(getattr(HTTPRequest, method)(target), response)
    finally:
        for http in connections:
            http.transmit()
        for response in responses:
            response.end.wait()
        for http in connections:
            http.close()
        if receiver:
            receiver.stop()


def post(prog, method, *args, arg_encoding="UTF-8", out=stdout):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri body".format(method))
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-r", "--rx-buffer-size", metavar="SIZE", default=4194304)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri")
    parser.add_argument("body")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave.http", level=INFO)
    if parsed.very_verbose:
        watch("shortwave.transmission", level=DEBUG)

    scheme, authority, path, query, fragment = parse_uri(parsed.uri.encode(arg_encoding))
    http = HTTP(authority, rx_buffer_size=parsed.rx_buffer_size, connection="close")
    target = build_uri(path=path, query=query, fragment=fragment)
    headers = {}
    if parsed.json:
        headers["content_type"] = b"application/json"
    try:
        response = ResponseWriter(out)
        http.append(HTTPRequest.post(target, parsed.body, **headers), response)
        http.transmit()
        response.end.wait()
    finally:
        http.close()


def put(prog, method, *args, arg_encoding="UTF-8", out=stdout):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri body".format(method))
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-r", "--rx-buffer-size", metavar="SIZE", default=4194304)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri")
    parser.add_argument("body")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave.http", level=INFO)
    if parsed.very_verbose:
        watch("shortwave.transmission", level=DEBUG)

    scheme, authority, path, query, fragment = parse_uri(parsed.uri.encode(arg_encoding))
    http = HTTP(authority, rx_buffer_size=parsed.rx_buffer_size, connection="close")
    target = build_uri(path=path, query=query, fragment=fragment)
    headers = {}
    if parsed.json:
        headers["content_type"] = b"application/json"
    try:
        response = ResponseWriter(out)
        http.append(HTTPRequest.put(target, parsed.body, **headers), response)
        http.transmit()
        response.end.wait()
    finally:
        http.close()


def delete(prog, method, *args, arg_encoding="UTF-8", out=stdout):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri".format(method))
    parser.add_argument("-r", "--rx-buffer-size", metavar="SIZE", default=4194304)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave.http", level=INFO)
    if parsed.very_verbose:
        watch("shortwave.transmission", level=DEBUG)

    scheme, authority, path, query, fragment = parse_uri(parsed.uri.encode(arg_encoding))
    http = HTTP(authority, rx_buffer_size=parsed.rx_buffer_size, connection="close")
    target = build_uri(path=path, query=query, fragment=fragment)
    headers = {}
    try:
        response = ResponseWriter(out)
        http.append(HTTPRequest.delete(target, **headers), response)
        http.transmit()
        response.end.wait()
    finally:
        http.close()


get = safe_request
head = safe_request


def main():
    argv[0] = "shortwave.http"
    if len(argv) == 1 or argv[1] == "help":
        usage()
    elif argv[1] == "get":
        get(*argv, arg_encoding=stdin.encoding, out=stdout)
    elif argv[1] == "head":
        head(*argv, arg_encoding=stdin.encoding, out=stdout)
    elif argv[1] == "post":
        post(*argv, arg_encoding=stdin.encoding, out=stdout)
    elif argv[1] == "put":
        put(*argv, arg_encoding=stdin.encoding, out=stdout)
    elif argv[1] == "delete":
        delete(*argv, arg_encoding=stdin.encoding, out=stdout)
    else:
        usage()


if __name__ == "__main__":
    main()
