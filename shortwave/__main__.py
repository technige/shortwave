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
from sys import argv, stdin, stdout

from shortwave import Connection
from shortwave.watcher import watch


def shortwave(prog, *args, encoding="ISO-8859-1", out=stdout):
    parser = ArgumentParser(prog)
    parser.add_argument("-v", "--verbose", action="count")
    parser.add_argument("authority")
    parsed = parser.parse_args(args)
    if parsed.verbose:
        watch("shortwave.transmission", level=DEBUG)
    with Connection(parsed.authority.encode(encoding), out=out) as connection:
        for line in stdin:
            connection.transmit(line.encode(encoding))


def main():
    shortwave("shortwave", *argv[1:], encoding=stdin.encoding, out=stdout)


if __name__ == "__main__":
    main()