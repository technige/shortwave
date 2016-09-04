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


LINUX = True

if LINUX:
    from .linux import \
        LinuxCorkingTransmitter as Transmitter, \
        LinuxEventPollReceiver as Receiver, \
        LinuxTransceiver as Transceiver
else:
    from .base import \
        BaseTransmitter as Transmitter, \
        BaseReceiver as Receiver, \
        BaseTransceiver as Transceiver


class Connection(Transceiver):
    """ A Connection applies structure to a Transceiver. This is primarily
    achieved through the presence of a buffer that is used to collect
    incoming data and deliver it in a controlled way via a programmable
    limiter.
    """

    data_limit = None

    def __init__(self, address, receiver=None, rx_buffer_size=None):
        super(Connection, self).__init__(address, receiver, rx_buffer_size)
        self.buffer = bytearray()

    def on_receive(self, view):
        from shortwave.compat import integer
        buffer = self.buffer
        buffer[len(buffer):] = view
        while buffer:
            data_limit = self.data_limit
            if data_limit is None:
                try:
                    self.on_data(buffer)
                finally:
                    del buffer[:]
            elif isinstance(data_limit, integer):
                try:
                    self.on_data(buffer[:data_limit])
                finally:
                    del buffer[:data_limit]
            elif isinstance(data_limit, bytes):
                end = buffer.find(data_limit)
                if end == -1:
                    break
                try:
                    self.on_data(buffer[:end])
                finally:
                    end += len(data_limit)
                    del buffer[:end]
            else:
                raise TypeError("Unsupported limiter %r" % data_limit)

    def on_data(self, data):
        pass
