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


from logging import DEBUG

from shortwave.transmission import Transceiver
from shortwave.util.watcher import watch


class Bolt(Transceiver):

    def ack_failure(self):
        self.transmitter.transmit(b"\x00\x02\xB0\x0E\x00\x00")

    def reset(self):
        self.transmitter.transmit(b"\x00\x02\xB0\x0F\x00\x00")

    def run(self, statement, parameters):
        pass

    def discard_all(self):
        self.transmitter.transmit(b"\x00\x02\xB0\x2F\x00\x00")

    def pull_all(self):
        self.transmitter.transmit(b"\x00\x02\xB0\x3F\x00\x00")

    def on_receive(self, view):
        pass

    def on_success(self, metadata):
        pass

    def on_record(self, values):
        pass

    def on_ignored(self, metadata):
        pass

    def on_failure(self, metadata):
        pass


def main():
    watch("shortwave", level=DEBUG)
    bolt = Bolt("neo4j:neo4j@127.0.0.1:7687")
    bolt.run("UNWIND range(1, 10) AS n RETURN n", {})
    bolt.pull_all()
    bolt.stop()


if __name__ == "__main__":
    main()