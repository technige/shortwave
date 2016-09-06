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

from __future__ import print_function

from shortwave.numbers import ECHO_PORT
from shortwave.transmission import Connection


class Echo(Connection):

    default_port = ECHO_PORT

    def __init__(self, authority, on_receive=lambda x: print(x.tobytes().decode("iso-8859-1"))):
        super(Echo, self).__init__(authority)
        self.on_receive = on_receive
