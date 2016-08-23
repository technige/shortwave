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
from logging import DEBUG
from sys import argv, stdout

from shortwave.http import HTTP
from shortwave.uri import parse_uri, build_uri
from shortwave.util.watcher import watch


def usage():
    print("usage: shortwave.http get <uri> [<uri> ...]")
    print("       shortwave.http post <uri> <body>")
    print("       shortwave.http put <uri> <body>")
    print("       shortwave.http delete <uri>")


def get(*uris, rx_buffer_size=None):
    watch("shortwave", level=DEBUG)
    responses = []
    try:
        for uri in uris:
            scheme, authority, path, query, fragment = parse_uri(uri)
            if scheme and scheme != b"http":
                raise ValueError("Non-HTTP URI: %r" % uri)
            if authority:
                http = HTTP(authority, rx_buffer_size)
            else:
                http = responses[-1][0]
            response = http.get(build_uri(path=path, query=query, fragment=fragment))
            responses.append((http, response))
    finally:
        for _, response in responses:
            data = response.read()
            stdout.write(data.decode(stdout.encoding))
        for http, _ in responses:
            http.close()


def post(uri, body, rx_buffer_size=None):
    watch("shortwave", level=DEBUG)
    scheme, authority, path, query, fragment = parse_uri(uri)
    http = HTTP(authority, rx_buffer_size, connection="close")
    try:
        with http.post(build_uri(path=path, query=query, fragment=fragment), body) as response:
            data = response.read()
            stdout.write(data.decode(stdout.encoding))
    finally:
        http.close()


def put(uri, body):
    watch("shortwave", level=DEBUG)
    scheme, authority, path, query, fragment = parse_uri(uri)
    http = HTTP(authority, connection="close")
    try:
        with http.put(build_uri(path=path, query=query, fragment=fragment), body) as response:
            data = response.read()
            stdout.write(data.decode(stdout.encoding))
    finally:
        http.close()


def delete(uri):
    watch("shortwave", level=DEBUG)
    scheme, authority, path, query, fragment = parse_uri(uri)
    http = HTTP(authority, connection="close")
    try:
        with http.delete(build_uri(path=path, query=query, fragment=fragment)) as response:
            response.read()
    finally:
        http.close()


def main():
    if len(argv) == 1 or argv[1] == "help":
        usage()
    elif argv[1] == "get":
        get(*argv[2:], rx_buffer_size=4194304)
    elif argv[1] == "post":
        post(*argv[2:], rx_buffer_size=4194304)
    elif argv[1] == "put":
        put(*argv[2:])
    elif argv[1] == "delete":
        delete(*argv[2:])
    else:
        usage()


if __name__ == "__main__":
    main()
