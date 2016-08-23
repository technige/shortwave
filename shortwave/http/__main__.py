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
from sys import argv, stdout

from shortwave.http import HTTP
from shortwave.uri import parse_uri, build_uri
from shortwave.util.watcher import watch


def usage():
    print("usage: shortwave.http get <uri> [<uri> ...]")
    print("       shortwave.http post <uri> <body>")
    print("       shortwave.http put <uri> <body>")
    print("       shortwave.http delete <uri>")


def get(prog, method, *args):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri [uri ...]".format(method))
    parser.add_argument("-1", "--single-receiver", action="store_true")
    parser.add_argument("-r", "--rx-buffer-size", metavar="SIZE", default=4194304)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri", nargs="+")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave", level=INFO)
    if parsed.very_verbose:
        watch("shortwave", level=DEBUG)
    if parsed.single_receiver:
        receiver = HTTP.Rx()
        receiver.start()
    else:
        receiver = None
    responses = []
    try:
        for uri in parsed.uri:
            scheme, authority, path, query, fragment = parse_uri(uri)
            if scheme and scheme != b"http":
                raise ValueError("Non-HTTP URI: %r" % uri)
            if authority:
                http = HTTP(authority, receiver, rx_buffer_size=parsed.rx_buffer_size)
            else:
                http = responses[-1][0]
            ref_uri = build_uri(path=path, query=query, fragment=fragment)
            response = http.get(ref_uri)
            responses.append((http, response))
    finally:
        for _, response in responses:
            data = response.read()
            stdout.write(data.decode(stdout.encoding))
        for http, _ in responses:
            http.close()
        if receiver:
            receiver.stop()


def post(prog, method, *args):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri body".format(method))
    parser.add_argument("-r", "--rx-buffer-size", metavar="SIZE", default=4194304)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri")
    parser.add_argument("body")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave", level=INFO)
    if parsed.very_verbose:
        watch("shortwave", level=DEBUG)
    scheme, authority, path, query, fragment = parse_uri(parsed.uri)
    http = HTTP(authority, rx_buffer_size=parsed.rx_buffer_size, connection="close")
    ref_uri = build_uri(path=path, query=query, fragment=fragment)
    try:
        with http.post(ref_uri, parsed.body) as response:
            data = response.read()
            stdout.write(data.decode(stdout.encoding))
    finally:
        http.close()


def put(prog, method, *args):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri body".format(method))
    parser.add_argument("-r", "--rx-buffer-size", metavar="SIZE", default=4194304)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri")
    parser.add_argument("body")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave", level=INFO)
    if parsed.very_verbose:
        watch("shortwave", level=DEBUG)
    scheme, authority, path, query, fragment = parse_uri(parsed.uri)
    http = HTTP(authority, rx_buffer_size=parsed.rx_buffer_size, connection="close")
    ref_uri = build_uri(path=path, query=query, fragment=fragment)
    try:
        with http.put(ref_uri, parsed.body) as response:
            data = response.read()
            stdout.write(data.decode(stdout.encoding))
    finally:
        http.close()


def delete(prog, method, *args):
    parser = ArgumentParser(prog, usage="%(prog)s {:s} [options] uri".format(method))
    parser.add_argument("-r", "--rx-buffer-size", metavar="SIZE", default=4194304)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-vv", "--very-verbose", action="store_true")
    parser.add_argument("uri")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave", level=INFO)
    if parsed.very_verbose:
        watch("shortwave", level=DEBUG)
    scheme, authority, path, query, fragment = parse_uri(parsed.uri)
    http = HTTP(authority, rx_buffer_size=parsed.rx_buffer_size, connection="close")
    ref_uri = build_uri(path=path, query=query, fragment=fragment)
    try:
        with http.delete(ref_uri) as response:
            data = response.read()
            stdout.write(data.decode(stdout.encoding))
    finally:
        http.close()


def main():
    argv[0] = "shortwave.http"
    if len(argv) == 1 or argv[1] == "help":
        usage()
    elif argv[1] == "get":
        get(*argv)
    elif argv[1] == "post":
        post(*argv)
    elif argv[1] == "put":
        put(*argv)
    elif argv[1] == "delete":
        delete(*argv)
    else:
        usage()


if __name__ == "__main__":
    main()
