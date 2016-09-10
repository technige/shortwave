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

from shortwave.transmission import Transceiver


class Connection(Transceiver):
    """ A Connection applies structure to a Transceiver. This is primarily
    achieved through the presence of a buffer that is used to collect
    incoming data and deliver it in a controlled way via a programmable
    limiter.
    """

    encoding = "ISO-8859-1"
    limiter = None

    def __init__(self, authority, default_port=None, on_data=None, receiver=None, out=None):
        super(Connection, self).__init__(authority, default_port, receiver)
        self.buffer = bytearray()
        if on_data is not None:
            self.on_data = on_data
        if out:
            self.out = out
        else:
            from sys import stdout
            self.out = stdout

    def on_receive(self, view):
        buffer = self.buffer
        buffer[len(buffer):] = view
        while buffer:
            limiter = self.limiter
            if limiter is None:
                try:
                    self.on_data(buffer)
                finally:
                    del buffer[:]
            elif callable(limiter):
                data = limiter(buffer)
                if data is not None:
                    try:
                        self.on_data(data)
                    finally:
                        pass
            else:
                raise TypeError("Unsupported limiter %r" % limiter)

    def on_data(self, data):
        out = self.out
        out.write(data.decode(self.encoding))


def line_limiter(eol):
    eol_size = len(eol)

    def f(buffer):
        p = buffer.find(eol)
        if p >= 0:
            data = buffer[:p]
            p += eol_size
            del buffer[:p]
            return data

    return f


def countdown_limiter(total):
    remaining = [total]

    def f(buffer):
        buffer_size = len(buffer)
        if buffer_size >= remaining[0]:
            data = buffer[:remaining[0]]
            del buffer[:remaining[0]]
            remaining[0] = 0
            return data
        elif buffer_size > 0:
            data = buffer[:]
            del buffer[:]
            remaining[0] -= buffer_size
            return data

    f.remaining = lambda: remaining[0]
    return f
