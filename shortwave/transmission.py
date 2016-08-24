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

from errno import ENOTCONN, EAGAIN, EBADF
from logging import getLogger
from select import epoll, EPOLLET, EPOLLIN, EPOLLHUP
from socket import socket as _socket, error as socket_error, \
    AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY, SHUT_RD, SHUT_WR
from threading import Thread

from shortwave.util.compat import integer
from shortwave.util.concurrency import sync

log = getLogger("shortwave")

default_buffer_size = 524288


class Transmitter(object):
    """ A Transmitter handles the outgoing half of a network conversation.
    Transmission is synchronous and will block until all data has been
    sent.
    """

    def __init__(self, socket, *args, **kwargs):
        self.socket = socket
        self.fd = self.socket.fileno()

    def transmit(self, *data):
        joined = b"".join(data)
        log.debug("T[%d]: %s", self.fd, joined)
        self.socket.sendall(joined)


class Receiver(Thread):
    """ An Receiver handles the incoming halves of one or more network
    conversations.
    """

    running = True

    def __init__(self):
        super(Receiver, self).__init__()
        self.clients = {}

    def __repr__(self):
        return "<%s at 0x%x>" % (self.__class__.__name__, id(self))

    def attach(self, transceiver, buffer_size):
        fd = transceiver.socket.fileno()
        buffer = bytearray(buffer_size or default_buffer_size)
        view = memoryview(buffer)
        self.clients[fd] = (transceiver, buffer, view)

    def run(self):
        pass

    def stop(self):
        pass


class EventPollReceiver(Receiver):
    """ An Receiver implementation that uses event polling (epoll).
    """

    def __init__(self):
        super(EventPollReceiver, self).__init__()
        self.poll = epoll()

    def attach(self, transceiver, buffer_size):
        fd = transceiver.socket.fileno()
        super(EventPollReceiver, self).attach(transceiver, buffer_size)
        self.poll.register(fd, EPOLLET | EPOLLIN)
        log.debug("R[%d]: ATTACHED %r (buffer_size=%d) TO %r", fd, transceiver, buffer_size, self)

    def run(self):
        log.debug("R[*]: STARTED %r", self)
        try:
            while not self.stopped():
                events = self.poll.poll(0.1)
                if self.stopped():
                    break
                for fd, event in events:
                    self._handle_event(fd, event)
        finally:
            self.poll.close()
            log.debug("R[*]: STOPPED %r", self)

    def _handle_event(self, fd, event):
        transceiver, buffer, view = self.clients[fd]
        if event & EPOLLIN:
            received = 0
            receiving = -1
            while receiving:
                try:
                    receiving = transceiver.socket.recv_into(buffer)
                except AttributeError:
                    # The socket has probably been closed
                    receiving = 0
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
                            log.debug("R[%d]: b*%d", fd, receiving)
                        else:
                            log.debug("R[%d]: %s", fd, bytes(buffer[:receiving]))
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

    @sync
    def stop(self):
        if self.running:
            log.debug("R[*]: STOPPING %r", self)
            self.running = False

    def stopped(self):
        return not self.running


class Transceiver(object):
    """ A Transceiver represents a two-way conversation by blending a
    Transmitter with a Receiver.
    """

    Tx = Transmitter
    Rx = EventPollReceiver  # TODO: adjust based on platform capabilities

    transmitter = None
    receiver = None

    def __init__(self, address, receiver=None, rx_buffer_size=None, *args, **kwargs):
        self.socket = new_socket(address)
        self.fd = self.socket.fileno()
        log.debug("X[%d]: CONNECT TO %s", self.fd, address)
        self.transmitter = self.Tx(self.socket, *args, **kwargs)
        if receiver:
            self.receiver = receiver
        else:
            self.receiver = self.Rx()
            self.receiver.stopped = lambda: self.stopped()
            self.receiver.start()
        self.receiver.attach(self, rx_buffer_size)

    def __del__(self):
        self.close()

    def transmit(self, *data):
        self.transmitter.transmit(*data)

    def stopped(self):
        return not self.transmitter and not self.receiver

    @sync
    def stop_tx(self):
        if self.transmitter:
            log.debug("T[%d]: STOP", self.fd)
            try:
                self.socket.shutdown(SHUT_WR)
            except socket_error as error:
                if error.errno not in (EBADF, ENOTCONN):
                    log.error("T[%d]: %s", self.fd, error)
            finally:
                self.transmitter = None
                if self.stopped() and not self.close.locked():
                    self.close()

    @sync
    def stop_rx(self):
        if self.receiver:
            try:
                self.on_stop()
            finally:
                log.debug("R[%d]: STOP", self.fd)
                try:
                    self.socket.shutdown(SHUT_RD)
                except socket_error as error:
                    if error.errno not in (EBADF, ENOTCONN):
                        log.error("R[%d]: %s", self.fd, error)
                finally:
                    self.receiver = None
                    if self.stopped() and not self.close.locked():
                        self.close()

    @sync
    def close(self):
        if self.socket:
            if not self.stop_tx.locked():
                self.stop_tx()
            if not self.stop_rx.locked():
                self.stop_rx()
            log.debug("X[%d]: CLOSE", self.fd)
            try:
                self.socket.close()
            except socket_error as error:
                log.error("X[%d]: %s", self.fd, error)
            finally:
                self.socket = None

    def on_receive(self, view):
        pass

    def on_stop(self):
        pass


class Connection(Transceiver):
    """ A Connection applies structure to a Transceiver. This is primarily
    achieved through the presence of a buffer that is used to collect
    incoming data and deliver it in a controlled way via a programmable
    limiter.
    """

    data_limit = None

    def __init__(self, address, receiver=None, rx_buffer_size=None, *args, **kwargs):
        super(Connection, self).__init__(address, receiver, rx_buffer_size, *args, **kwargs)
        self.buffer = bytearray()

    def on_receive(self, view):
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


def new_socket(address):
    socket = _socket(AF_INET, SOCK_STREAM)
    socket.connect(address)
    socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    socket.setblocking(0)
    return socket
