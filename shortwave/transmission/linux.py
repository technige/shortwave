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

from errno import EAGAIN, EBADF
from logging import getLogger
from socket import IPPROTO_TCP, TCP_CORK, error as socket_error
from select import epoll, EPOLLET, EPOLLIN, EPOLLHUP
from ssl import SSLWantReadError

from shortwave.transmission.base import BaseTransmitter, BaseReceiver, BaseTransceiver

log = getLogger("shortwave.transmission")

default_buffer_size = 524288


class LinuxCorkingTransmitter(BaseTransmitter):
    """ A Transmitter handles the outgoing half of a network conversation.
    Transmission is synchronous and will block until all data has been
    sent.
    """

    def transmit(self, *data):
        self.socket.setsockopt(IPPROTO_TCP, TCP_CORK, 1)
        super(LinuxCorkingTransmitter, self).transmit(*data)
        self.socket.setsockopt(IPPROTO_TCP, TCP_CORK, 0)


class LinuxEventPollReceiver(BaseReceiver):
    """ An Receiver implementation that uses event polling (epoll).
    """

    def __init__(self):
        super(LinuxEventPollReceiver, self).__init__()
        self._poll = epoll()

    def attach(self, transceiver):
        fd = transceiver.socket.fileno()
        self._poll.register(fd, EPOLLET | EPOLLIN)
        super(LinuxEventPollReceiver, self).attach(transceiver)

    def run(self):
        log.debug("Started %r", self)
        poll = self._poll.poll
        try:
            while not self.stopped():
                events = poll(0.1)
                if self.stopped():
                    break
                for fd, event in events:
                    self._handle_event(fd, event)
        finally:
            self._poll.close()
            log.debug("Stopped %r", self)

    def _handle_event(self, fd, event):
        transceiver_ref, buffer, view = self.clients[fd]
        transceiver = transceiver_ref()
        if transceiver is None:
            return
        if event & EPOLLIN:
            received = 0
            receiving = -1
            while receiving:
                try:
                    receiving = transceiver.socket.recv_into(buffer)
                except AttributeError:
                    # The socket has probably been closed
                    receiving = 0
                except SSLWantReadError:
                    # Not enough data, let's go round again
                    continue
                except socket_error as error:
                    if error.errno in (EAGAIN, EBADF):
                        # EBADF: The socket has probably been disconnected in between
                        # the event being raised and getting here.
                        # EAGAIN: We've simply run out of data to read
                        receiving = 0
                    else:
                        log.error("R[%d]: %s", fd, error)
                        raise
                else:
                    if receiving:
                        if receiving > 1024:
                            log.info("R[%d]: b*%d", fd, receiving)
                        else:
                            log.info("R[%d]: %s", fd, bytes(buffer[:receiving]))
                        try:
                            transceiver.on_receive(view[:receiving])
                        finally:
                            received += receiving
            if not received:
                transceiver.stop_rx()
        elif event & EPOLLHUP:
            transceiver.stop_rx()
        else:
            log.error("R[%d]: Unknown event %r", fd, event)
            raise RuntimeError(event)


class LinuxTransceiver(BaseTransceiver):
    """ A Transceiver represents a two-way conversation by blending a
    Transmitter with a Receiver.
    """

    Tx = LinuxCorkingTransmitter
    Rx = LinuxEventPollReceiver
