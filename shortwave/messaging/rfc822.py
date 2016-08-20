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

from shortwave.util.compat import bstr, xstr, SPACE


SP = b" "
CR = b"\r"
LF = b"\n"
COLON = b":"
SLASH = b"/"
AT_SIGN = b"@"
NUMBER_SIGN = b"#"
QUESTION_MARK = b"?"

CR_LF = CR + LF
SLASH_SLASH = SLASH + SLASH


# Dictionary of known headers
header_names = {
    "bcc": b"bcc",
    "cc": b"cc",
    "comments": b"Comments",
    "date": b"Date",
    "encrypted": b"Encrypted",
    "from": b"From",
    "in_reply_to": b"In-Reply-To",
    "keywords": b"Keywords",
    "message_id": b"Message-ID",
    "received": b"Received",
    "references": b"References",
    "reply_to": b"Reply-To",
    "resent_bcc": b"Resent-bcc",
    "resent_cc": b"Resent-cc",
    "resent_date": b"Resent-Date",
    "resent_from": b"Resent-From",
    "resent_message_id": b"Resent-Message-ID",
    "resent_reply_to": b"Resent-Reply-To",
    "resent_sender": b"Resent-Sender",
    "resent_to": b"Resent-To",
    "return_path": b"Return-Path",
    "sender": b"Sender",
    "subject": b"Subject",
    "to": b"To",
}


class HeaderDict(dict):

    @classmethod
    def from_bytes(cls, b):
        # TODO
        pass

    def __init__(self, iterable=None, **kwargs):
        super(HeaderDict, self).__init__()
        self.update(iterable, **kwargs)

    def __repr__(self):
        return xstr(self.to_bytes())

    def __getitem__(self, name):
        matchable_name, _ = header_name(name)
        _, value = super(HeaderDict, self).__getitem__(matchable_name)
        return value

    def __setitem__(self, name, value):
        matchable_name, canonical_name = header_name(name)
        if isinstance(value, bytes):
            super(HeaderDict, self).__setitem__(matchable_name, (canonical_name, value))
        else:
            super(HeaderDict, self).__setitem__(matchable_name, (canonical_name, bstr(value)))

    def __delitem__(self, name):
        matchable_name, _ = header_name(name)
        super(HeaderDict, self).__delitem__(matchable_name)

    def copy(self):
        return self.__class__(self)

    def get(self, name, default=None):
        matchable_name, _ = header_name(name)
        try:
            _, value = super(HeaderDict, self).__getitem__(matchable_name)
        except KeyError:
            return default
        else:
            return value

    def update(self, other=None, **kwargs):
        if other:
            try:
                for name in other.keys():
                    self[name] = other[name]
            except AttributeError:
                for name, value in other:
                    self[name] = value
        for name in kwargs:
            self[name] = kwargs[name]

    def items(self):
        return list(super(HeaderDict, self).values())

    def keys(self):
        return list(canonical_name for canonical_name, _ in super(HeaderDict, self).values())

    def values(self):
        return list(value for _, value in super(HeaderDict, self).values())

    def to_bytes(self):
        return b"".join(b"%s: %s%s" % (name, value, CR_LF) for name, value in sorted(self.items()))


def parse_header(value):
    if value is None:
        return None, None
    if not isinstance(value, bytes):
        value = bstr(value)
    p = 0
    delimiter = value.find(b";", p)
    eol = len(value)
    if p <= delimiter < eol:
        string_value = value[p:delimiter]
        params = {}
        while delimiter < eol:
            # Skip whitespace after previous delimiter
            p = delimiter + 1
            while p < eol and value[p] == SPACE:
                p += 1
            # Find next delimiter
            delimiter = value.find(b";", p)
            if delimiter == -1:
                delimiter = eol
            # Add parameter
            eq = value.find(b"=", p)
            if p <= eq < delimiter:
                params[value[p:eq]] = value[(eq + 1):delimiter]
            elif p < delimiter:
                params[value[p:delimiter]] = None
    else:
        string_value = value[p:]
        params = {}
    return string_value, params


def header_name(name):
    """ Normalise a header name to produce a string variant usable for
    matching and a byte variant with canonical casing.

    :param name:
    :return:
    """
    matchable_name = xstr(name).replace("-", "_").lower()
    try:
        canonical_name = header_names[matchable_name]
    except KeyError:
        canonical_name = bstr(name).replace(b"_", b"-").title()
    return matchable_name, canonical_name


def internet_time(value):
    # TODO
    return bstr(value)
