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

from shortwave.http import HTTP, post
from shortwave.util.watcher import watch


def main():
    watch("shortwave", level=DEBUG)
    # http = HTTP("neo4j:neo4j@127.0.0.1:7474")
    # http.on_end = lambda: http.close()
    # http.post(b"/db/data/cypher", {"query": "UNWIND range(1, 2000) AS n RETURN n"})
    # http.finish()
    post(b"http://neo4j:neo4j@127.0.0.1:7474/db/data/cypher", {"query": "UNWIND range(1, 2000) AS n RETURN n"})


if __name__ == "__main__":
    main()
