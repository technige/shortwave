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
from select import epoll, EPOLLET, EPOLLIN
from socket import socket as _socket, error as socket_error, \
    AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY, SHUT_RD, SHUT_WR
from threading import Thread

from shortwave.util.compat import integer


log = getLogger("shortwave")


class Transmitter(object):

    finished = False

    def __init__(self, socket, *args, **kwargs):
        self.socket = socket

    def transmit(self, *data):
        joined = b"".join(data)
        log.debug("Tx: %s", joined)
        self.socket.sendall(joined)

    def finish(self):
        if not self.finished:
            self.socket.shutdown(SHUT_WR)
            self.finished = True


class EventPollReceiver(Thread):

    running = True

    def __init__(self):
        super(EventPollReceiver, self).__init__()
        self.clients = {}
        self.poll = epoll()

    def __len__(self):
        return len(self.clients)

    def attach(self, socket, on_receive, on_finish, buffer_size=8192):
        fd = socket.fileno()
        buffer = bytearray(buffer_size)
        view = memoryview(buffer)
        self.clients[fd] = (socket, buffer, view, on_receive, on_finish)
        self.poll.register(fd, EPOLLET | EPOLLIN)

    def detach(self, socket):
        fd = socket.fileno()
        try:
            socket.shutdown(SHUT_RD)
        except socket_error as error:
            if error.errno == 107:
                # they must have closed first
                pass
            else:
                raise
        self.poll.unregister(fd)
        del self.clients[fd]

    def run(self):
        while self.running:
            events = self.poll.poll(1)
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
                            if error.errno == 11:
                                pass
                            else:
                                raise
                        else:
                            if receiving:
                                log.debug("Rx: %s", bytes(buffer[:receiving]))
                                on_receive(view[:receiving])
                                received += receiving
                    if not received:
                        on_finish()
                else:
                    raise RuntimeError(event)

    def stop(self):
        for fd in list(self.clients):
            self.detach(self.clients[fd][0])
        self.poll.close()
        self.running = False


Receiver = EventPollReceiver


class Transmission(object):
    Tx = Transmitter
    Rx = Receiver

    def __init__(self, address, *args, **kwargs):
        self.socket = new_socket(address)
        self.transmitter = self.Tx(self.socket, *args, **kwargs)
        self.receiver = new_single_use_receiver(self)
        self.receiver.start()

    def transmit(self, *data):
        self.transmitter.transmit(*data)

    def finish(self):
        self.transmitter.finish()

    def on_receive(self, view):
        pass

    def on_finish(self):
        pass


class Protocol(Transmission):

    def __init__(self, address, *args, **kwargs):
        super(Protocol, self).__init__(address, *args, **kwargs)
        self.buffer = bytearray()
        self.limit = None

    def on_receive(self, view):
        buffer = self.buffer
        buffer[len(buffer):] = view
        while self.buffer:
            limit = self.limit
            if limit is None:
                self.on_data(buffer)
                self.buffer.clear()
            elif isinstance(limit, integer):
                if len(buffer) < limit:
                    break
                self.on_data(buffer[:limit])
                del buffer[:limit]
            elif isinstance(limit, bytes):
                end = self.buffer.find(limit)
                if end == -1:
                    break
                self.on_data(self.buffer[:end])
                end += len(limit)
                del self.buffer[:end]
            else:
                raise TypeError("Unsupported limit %r" % limit)

    def on_data(self, data):
        pass


def new_socket(address):
    socket = _socket(AF_INET, SOCK_STREAM)
    socket.connect(address)
    socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    socket.setblocking(0)
    return socket


def new_single_use_receiver(protocol):
    receiver = protocol.Rx()

    def on_finish():
        protocol.on_finish()
        receiver.stop()
        protocol.socket.close()

    receiver.attach(protocol.socket, protocol.on_receive, on_finish)
    return receiver
