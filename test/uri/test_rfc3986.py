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

from collections import OrderedDict
from unittest import TestCase

from shortwave.uri.rfc3986 import percent_encode, percent_decode, parse_uri, resolve_uri, uri, \
    parse_uri_authority
from shortwave.util.compat import ustr


class PercentEncodeTestCase(TestCase):
    def test_can_percent_encode_none(self):
        encoded = percent_encode(None)
        assert encoded is None

    def test_can_percent_encode_empty_string(self):
        encoded = percent_encode("")
        assert encoded == b""

    def test_can_percent_encode_number(self):
        encoded = percent_encode(12)
        assert encoded == b"12"

    def test_can_percent_encode_string(self):
        encoded = percent_encode("foo")
        assert encoded == b"foo"

    def test_can_percent_encode_bytes(self):
        encoded = percent_encode(b"foo")
        assert encoded == b"foo"

    def test_can_percent_encode_unicode(self):
        encoded = percent_encode(ustr("foo"))
        assert encoded == b"foo"

    def test_can_percent_encode_list(self):
        encoded = percent_encode(["knife&fork", "spoon"])
        assert encoded == b"knife%26fork&spoon"

    def test_can_percent_encode_dictionary(self):
        encoded = percent_encode(OrderedDict([("one", 1), ("two", 2)]))
        assert encoded == b"one=1&two=2"

    def test_can_percent_encode_reserved_chars(self):
        encoded = percent_encode("20% of $100 = $20")
        assert encoded == b"20%25%20of%20%24100%20%3D%20%2420"

    def test_can_percent_encode_extended_chars(self):
        encoded = percent_encode("/El Niño/")
        assert encoded == b"%2FEl%20Ni%C3%B1o%2F"

    def test_can_percent_encode_with_safe_chars(self):
        encoded = percent_encode("/El Niño/", safe="/|\\")
        assert encoded == b"/El%20Ni%C3%B1o/"


class PercentDecodeTestCase(TestCase):
    def test_can_percent_decode_none(self):
        decoded = percent_decode(None)
        assert decoded is None

    def test_can_percent_decode_empty_string(self):
        decoded = percent_decode("")
        assert decoded == ""

    def test_can_percent_decode_number(self):
        decoded = percent_decode(12)
        assert decoded == "12"

    def test_can_percent_decode_string(self):
        decoded = percent_decode("foo")
        assert decoded == "foo"

    def test_can_percent_decode_bytes(self):
        decoded = percent_decode(b"foo")
        assert decoded == "foo"

    def test_can_percent_decode_unicode(self):
        decoded = percent_decode(ustr("foo"))
        assert decoded == "foo"

    def test_can_percent_decode_plus_to_space(self):
        decoded = percent_decode("one+two%20three+four")
        assert decoded == "one two three four"

    def test_can_percent_decode_reserved_chars(self):
        decoded = percent_decode("20%25%20of%20%24100%20%3D%20%2420")
        assert decoded == "20% of $100 = $20"

    def test_can_percent_decode_extended_chars(self):
        decoded = percent_decode("El%20Ni%C3%B1o")
        assert decoded == "El Niño"

    def test_partially_decoded_chars_use_replacement_char(self):
        decoded = percent_decode("El%20Ni%C3")
        assert decoded == "El Ni�"


class ParseAuthorityTestCase(TestCase):
    """    
    """
    
    def test_can_parse_none_authority(self):
        user_info, host, port = parse_uri_authority(None)
        assert user_info is None
        assert host is None
        assert port is None
        
    def test_can_parse_empty_authority(self):
        user_info, host, port = parse_uri_authority("")
        assert user_info is None
        assert host == b""
        assert port is None
        
    def test_can_parse_host_authority(self):
        user_info, host, port = parse_uri_authority("example.com")
        assert user_info is None
        assert host == b"example.com"
        assert port is None
        
    def test_can_parse_host_port_authority(self):
        user_info, host, port = parse_uri_authority("example.com:6789")
        assert user_info is None
        assert host == b"example.com"
        assert port == 6789
        
    def test_can_parse_user_host_authority(self):
        user_info, host, port = parse_uri_authority("bob@example.com")
        assert user_info == b"bob"
        assert host == b"example.com"
        assert port is None
        
    def test_can_parse_email_user_host_authority(self):
        user_info, host, port = parse_uri_authority("bob@example.com@example.com")
        assert user_info == b"bob@example.com"
        assert host == b"example.com"
        assert port is None
        
    def test_can_parse_full_authority(self):
        user_info, host, port = parse_uri_authority("bob@example.com:6789")
        assert user_info == b"bob"
        assert host == b"example.com"
        assert port == 6789
        

class ParseURITestCase(TestCase):
    def test_can_parse_none_uri(self):
        scheme, authority, path, query, fragment = parse_uri(None)
        assert scheme is None
        assert authority is None
        assert path is None
        assert query is None
        assert fragment is None

    def test_can_parse_empty_string_uri(self):
        scheme, authority, path, query, fragment = parse_uri("")
        assert scheme is None
        assert authority is None
        assert path == b""
        assert query is None
        assert fragment is None

    def test_can_parse_absolute_path_uri(self):
        scheme, authority, path, query, fragment = parse_uri("/foo/bar")
        assert scheme is None
        assert authority is None
        assert path == b"/foo/bar"
        assert query is None
        assert fragment is None

    def test_can_parse_relative_path_uri(self):
        scheme, authority, path, query, fragment = parse_uri("foo/bar")
        assert scheme is None
        assert authority is None
        assert path == b"foo/bar"
        assert query is None
        assert fragment is None

    def test_can_parse_only_query(self):
        scheme, authority, path, query, fragment = parse_uri("?foo=bar")
        assert scheme is None
        assert authority is None
        assert path == b""
        assert query == b"foo=bar"
        assert fragment is None

    def test_can_parse_only_fragment(self):
        scheme, authority, path, query, fragment = parse_uri("#foo")
        assert scheme is None
        assert authority is None
        assert path == b""
        assert query is None
        assert fragment == b"foo"

    def test_can_parse_uri_without_scheme(self):
        scheme, authority, path, query, fragment = parse_uri("//example.com")
        assert scheme is None
        assert authority == b"example.com"
        assert path == b""
        assert query is None
        assert fragment is None

    def test_can_parse_simple_uri(self):
        scheme, authority, path, query, fragment = parse_uri("foo://example.com")
        assert scheme == b"foo"
        assert authority == b"example.com"
        assert path == b""
        assert query is None
        assert fragment is None

    def test_can_parse_uri_with_extended_chars(self):
        scheme, authority, path, query, fragment = parse_uri("foo://éxamplə.çôm/foo")
        assert scheme == b"foo"
        assert authority == "éxamplə.çôm".encode("utf-8")
        assert path == b"/foo"
        assert query is None
        assert fragment is None

    def test_can_parse_uri_with_root_path(self):
        scheme, authority, path, query, fragment = parse_uri("foo://example.com/")
        assert scheme == b"foo"
        assert authority == b"example.com"
        assert path == b"/"
        assert query is None
        assert fragment is None

    def test_can_parse_full_uri(self):
        scheme, authority, path, query, fragment = parse_uri("foo://bob@somewhere@example.com:8042"
                                                             "/over/there?name=ferret#nose")
        assert scheme == b"foo"
        assert authority == b"bob@somewhere@example.com:8042"
        assert path == b"/over/there"
        assert query == b"name=ferret"
        assert fragment == b"nose"


class ReferenceResolutionTestCase(TestCase):
    """ RFC 3986, section 5.4.
    """

    base_uri = "http://a/b/c/d;p?q"

    def resolve_references(self, references, strict=True):
        for reference, target in references.items():
            print(reference, "->", target)
            resolved = resolve_uri(self.base_uri, reference, strict)
            assert resolved == target

    def test_normal_examples(self):
        """ 5.4.1.  Normal Examples
        """

        self.resolve_references({
            "g:h": b"g:h",
            "g": b"http://a/b/c/g",
            "./g": b"http://a/b/c/g",
            "g/": b"http://a/b/c/g/",
            "/g": b"http://a/g",
            "//g": b"http://g",
            "?y": b"http://a/b/c/d;p?y",
            "g?y": b"http://a/b/c/g?y",
            "#s": b"http://a/b/c/d;p?q#s",
            "g#s": b"http://a/b/c/g#s",
            "g?y#s": b"http://a/b/c/g?y#s",
            ";x": b"http://a/b/c/;x",
            "g;x": b"http://a/b/c/g;x",
            "g;x?y#s": b"http://a/b/c/g;x?y#s",
            "": b"http://a/b/c/d;p?q",
            ".": b"http://a/b/c/",
            "./": b"http://a/b/c/",
            "..": b"http://a/b/",
            "../": b"http://a/b/",
            "../g": b"http://a/b/g",
            "../..": b"http://a/",
            "../../": b"http://a/",
            "../../g": b"http://a/g",
        })

    def test_abnormal_examples(self):
        """ 5.4.2.  Abnormal Examples
        """

        # Although the following abnormal examples are unlikely to occur in
        # normal practice, all URI parsers should be capable of resolving them
        # consistently.  Each example uses the same base as that above.
        #
        # Parsers must be careful in handling cases where there are more ".."
        # segments in a relative-path reference than there are hierarchical
        # levels in the base URI's path.  Note that the ".." syntax cannot be
        # used to change the authority component of a URI.
        self.resolve_references({
            "../../../g": b"http://a/g",
            "../../../../g": b"http://a/g",
        })

        # Similarly, parsers must remove the dot-segments "." and ".." when
        # they are complete components of a path, but not when they are only
        # part of a segment.
        self.resolve_references({
            "/./g": b"http://a/g",
            "/../g": b"http://a/g",
            "g.": b"http://a/b/c/g.",
            ".g": b"http://a/b/c/.g",
            "g..": b"http://a/b/c/g..",
            "..g": b"http://a/b/c/..g",
        })

        # Less likely are cases where the relative reference uses unnecessary
        # or nonsensical forms of the "." and ".." complete path segments.
        self.resolve_references({
            "./../g": b"http://a/b/g",
            "./g/.": b"http://a/b/c/g/",
            "g/./h": b"http://a/b/c/g/h",
            "g/../h": b"http://a/b/c/h",
            "g;x=1/./y": b"http://a/b/c/g;x=1/y",
            "g;x=1/../y": b"http://a/b/c/y",
        })

        # Some applications fail to separate the reference's query and/or
        # fragment components from the path component before merging it with
        # the base path and removing dot-segments.  This error is rarely
        # noticed, as typical usage of a fragment never includes the hierarchy
        # ("/") character and the query component is not normally used within
        # relative references.
        self.resolve_references({
            "g?y/./x": b"http://a/b/c/g?y/./x",
            "g?y/../x": b"http://a/b/c/g?y/../x",
            "g#s/./x": b"http://a/b/c/g#s/./x",
            "g#s/../x": b"http://a/b/c/g#s/../x",
        })

        # Some parsers allow the scheme name to be present in a relative
        # reference if it is the same as the base URI scheme.  This is
        # considered to be a loophole in prior specifications of partial URI
        # [RFC1630].  Its use should be avoided but is allowed for backward
        # compatibility.
        #
        # for strict parsers:
        self.resolve_references({"http:g": b"http:g"}, strict=True)
        #
        # for backward compatibility:
        self.resolve_references({"http:g": b"http://a/b/c/g"}, strict=False)

    def test_can_resolve_from_empty_path(self):
        base = "http://example.com"
        uri = resolve_uri(base, "foo")
        assert uri == b"http://example.com/foo"

    def test_can_resolve_from_empty_uri(self):
        base = ""
        uri = resolve_uri(base, "foo")
        assert uri == b"foo"

    def test_resolving_when_reference_is_none_returns_none(self):
        base = "http://example.com"
        uri = resolve_uri(base, None)
        assert uri is None


class URIConstructionTestCase(TestCase):
    """
    """

    def test_can_build_empty_uri(self):
        built = uri()
        assert built is b""

    def test_can_build_uri_from_string(self):
        built = uri(uri="foo://example.com/")
        assert built == b"foo://example.com/"

    def test_can_build_uri_from_hierarchical_part(self):
        built = uri(hierarchical_part="//example.com/")
        assert built == b"//example.com/"

    def test_can_build_uri_from_scheme_and_hierarchical_part(self):
        built = uri(scheme="foo", hierarchical_part="//example.com/")
        assert built == b"foo://example.com/"

    def test_can_build_uri_from_scheme_hierarchical_part_and_query(self):
        built = uri(scheme="foo", hierarchical_part="//example.com/", query="spam=eggs")
        assert built == b"foo://example.com/?spam=eggs"

    def test_can_build_uri_from_scheme_hierarchical_part_query_and_fragment(self):
        built = uri(scheme="foo", hierarchical_part="//example.com/", query="spam=eggs",
                    fragment="mustard")
        assert built == b"foo://example.com/?spam=eggs#mustard"

    def test_can_build_uri_from_absolute_path_reference(self):
        built = uri(absolute_path_reference="/foo/bar?spam=eggs#mustard")
        assert built == b"/foo/bar?spam=eggs#mustard"

    def test_can_build_uri_from_authority_and_absolute_path_reference(self):
        built = uri(authority="bob@example.com:9999",
                    absolute_path_reference="/foo/bar?spam=eggs#mustard")
        assert built == b"//bob@example.com:9999/foo/bar?spam=eggs#mustard"

    def test_can_build_uri_from_scheme_host_and_path(self):
        built = uri(scheme="http", host="example.com", path="/foo/bar")
        assert built == b"http://example.com/foo/bar"

    def test_can_build_uri_from_scheme_and_host_port(self):
        built = uri(scheme="http", host_port="example.com:3456")
        assert built == b"http://example.com:3456"

    def test_can_build_uri_from_scheme_authority_and_host_port(self):
        built = uri(scheme="http", authority="bob@example.net:4567", host_port="example.com:3456")
        assert built == b"http://bob@example.com:3456"

    def test_can_build_uri_from_scheme_user_info_and_host_port(self):
        built = uri(scheme="http", user_info="bob", host_port="example.com:3456")
        assert built == b"http://bob@example.com:3456"

    def test_can_build_uri_from_scheme_user_info_and_path(self):
        built = uri(scheme="http", user_info="bob", path="/foo")
        assert built == b"http://bob@/foo"

    def test_can_build_uri_from_scheme_authority_and_host(self):
        built = uri(scheme="http", authority="bob@example.net", host="example.com")
        assert built == b"http://bob@example.com"

    def test_can_build_uri_from_scheme_authority_and_port(self):
        built = uri(scheme="http", authority="bob@example.com", port=3456)
        assert built == b"http://bob@example.com:3456"

    def test_can_build_uri_from_scheme_port_and_path(self):
        built = uri(scheme="http", port=3456, path="/foo")
        assert built == b"http://:3456/foo"
