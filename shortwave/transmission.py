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

from logging import getLogger
from select import epoll, EPOLLET, EPOLLIN, EPOLLHUP
from socket import socket as _socket, error as socket_error, \
    AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY, SHUT_RD, SHUT_WR
from threading import Thread

from shortwave.util.compat import integer


log = getLogger("shortwave")


class Transmitter(object):
    """ A Transmitter handles the outgoing half of a network conversation.
    Transmission is synchronous and will block until all data has been
    sent.
    """

    stopped = False

    def __init__(self, socket, *args, **kwargs):
        self.socket = socket
        self.fd = self.socket.fileno()

    def transmit(self, *data):
        joined = b"".join(data)
        log.debug("T[%d]: %s", self.fd, joined)
        self.socket.sendall(joined)

    def stop(self):
        if not self.stopped:
            log.debug("T[%d]: STOP", self.fd)
            try:
                self.socket.shutdown(SHUT_WR)
            except socket_error as error:
                log.error("T[%d]: %s", self.fd, error)
            finally:
                self.stopped = True


class Receiver(Thread):
    """ An Receiver handles the incoming halves of one or more network
    conversations.
    """

    def __init__(self):
        super(Receiver, self).__init__()
        self.clients = {}

    def __len__(self):
        return len(self.clients)

    def register(self, socket, on_receive, on_finish, buffer_size=8192):
        fd = socket.fileno()
        buffer = bytearray(buffer_size)
        view = memoryview(buffer)
        self.clients[fd] = (socket, buffer, view, on_receive, on_finish)

    def run(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()


class EventPollReceiver(Receiver):
    """ An implementation of Receiver that uses epoll.
    """

    def __init__(self):
        super(EventPollReceiver, self).__init__()
        self.poll = epoll()

    def register(self, socket, on_receive, on_finish, buffer_size=8192):
        super(EventPollReceiver, self).register(socket, on_receive, on_finish, buffer_size)
        fd = socket.fileno()
        log.debug("R[%d]: REGISTER WITH %r", fd, self)
        self.poll.register(fd, EPOLLET | EPOLLIN)

    def run(self):
        try:
            while self.clients:
                events = self.poll.poll(3)
                if not self.clients:
                    break
                for fd, event in events:
                    socket, buffer, view, on_receive, on_finish = self.clients[fd]
                    recv_into = socket.recv_into
                    if event & EPOLLIN:
                        received = 0
                        receiving = -1
                        while receiving:
                            try:
                                receiving = recv_into(buffer)
                            except socket_error as error:
                                if error.errno == 9:
                                    receiving = 0
                                elif error.errno == 11:
                                    log.warn("R[%d]: TRY AGAIN", fd)
                                else:
                                    log.error("R[%d]: %s", fd, error)
                                    raise
                            else:
                                if receiving:
                                    if receiving > 78:
                                        log.debug("R[%d]: b*%d", fd, receiving)
                                    else:
                                        log.debug("R[%d]: %s", fd, bytes(buffer[:receiving]))
                                    on_receive(view[:receiving])
                                    received += receiving
                        if not received:
                            log.debug("R[%d]: STOP", fd)
                            del self.clients[fd]
                            on_finish()
                    elif event & EPOLLHUP:
                        log.debug("R[%d]: HANG UP", fd)
                        del self.clients[fd]
                        on_finish()
                    else:
                        raise RuntimeError(event)
        finally:
            self.poll.close()

    def stop(self):
        self.clients.clear()


class Transceiver(object):
    """ A Transceiver represents a two-way conversation by blending a
    Transmitter with a Receiver.
    """

    Tx = Transmitter
    Rx = EventPollReceiver  # TODO: adjust based on platform capabilities

    def __init__(self, address, *args, **kwargs):
        self.socket = new_socket(address)
        self.fd = self.socket.fileno()
        log.debug("X[%d]: CONNECT TO %s", self.fd, address)
        self.transmitter = self.Tx(self.socket, *args, **kwargs)
        self.receiver = new_single_use_receiver(self)
        self.receiver.start()

    def __del__(self):
        self.close()

    def transmit(self, *data):
        self.transmitter.transmit(*data)

    def stop(self):
        self.transmitter.stop()

    def close(self):
        log.debug("X[%d]: DISCONNECT", self.fd)
        self.stop()
        try:
            self.socket.close()
        except socket_error as error:
            log.error("X[%d]: %s", self.fd, error)

    def on_receive(self, view):
        pass

    def on_finish(self):
        pass


class Connection(Transceiver):
    """ A Connection applies structure to a Transceiver. This is primarily
    achieved through the presence of a buffer that is used to collect
    incoming data and deliver it in a controlled way via a programmable
    limiter.
    """

    limit = None

    def __init__(self, address, *args, **kwargs):
        super(Connection, self).__init__(address, *args, **kwargs)
        self.buffer = bytearray()

    def on_receive(self, view):
        buffer = self.buffer
        buffer[len(buffer):] = view
        while buffer:
            limit = self.limit
            if limit is None:
                self.on_data(buffer)
                del buffer[:]
            elif isinstance(limit, integer):
                if len(buffer) < limit:
                    break
                self.on_data(buffer[:limit])
                del buffer[:limit]
            elif isinstance(limit, bytes):
                end = buffer.find(limit)
                if end == -1:
                    break
                self.on_data(buffer[:end])
                end += len(limit)
                del buffer[:end]
            else:
                raise TypeError("Unsupported limiter %r" % limit)

    def on_data(self, data):
        pass


def new_socket(address):
    socket = _socket(AF_INET, SOCK_STREAM)
    socket.connect(address)
    socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    socket.setblocking(0)
    return socket


def new_single_use_receiver(transceiver):
    receiver = transceiver.Rx()

    def on_finish():
        try:
            transceiver.on_finish()
            try:
                transceiver.socket.shutdown(SHUT_RD)
            except socket_error:
                pass
        finally:
            receiver.stop()

    receiver.register(transceiver.socket, transceiver.on_receive, on_finish)
    return receiver
