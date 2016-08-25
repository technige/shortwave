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

from shortwave.uri import percent_encode, percent_decode, parse_uri, resolve_uri, \
    build_uri, parse_authority, remove_dot_segments, parse_parameters, parse_path, expand_uri
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


class ParseURITestCase(TestCase):
    def test_can_parse_none_uri(self):
        scheme, authority, path, query, fragment = parse_uri(None)
        assert scheme is None
        assert authority is None
        assert path is None
        assert query is None
        assert fragment is None

    def test_can_parse_empty_string_uri(self):
        scheme, authority, path, query, fragment = parse_uri(b"")
        assert scheme is None
        assert authority is None
        assert path == b""
        assert query is None
        assert fragment is None

    def test_can_parse_absolute_path_uri(self):
        scheme, authority, path, query, fragment = parse_uri(b"/foo/bar")
        assert scheme is None
        assert authority is None
        assert path == b"/foo/bar"
        assert query is None
        assert fragment is None

    def test_can_parse_relative_path_uri(self):
        scheme, authority, path, query, fragment = parse_uri(b"foo/bar")
        assert scheme is None
        assert authority is None
        assert path == b"foo/bar"
        assert query is None
        assert fragment is None

    def test_can_parse_only_query(self):
        scheme, authority, path, query, fragment = parse_uri(b"?foo=bar")
        assert scheme is None
        assert authority is None
        assert path == b""
        assert query == b"foo=bar"
        assert fragment is None

    def test_can_parse_only_fragment(self):
        scheme, authority, path, query, fragment = parse_uri(b"#foo")
        assert scheme is None
        assert authority is None
        assert path == b""
        assert query is None
        assert fragment == b"foo"

    def test_can_parse_uri_without_scheme(self):
        scheme, authority, path, query, fragment = parse_uri(b"//example.com")
        assert scheme is None
        assert authority == b"example.com"
        assert path == b""
        assert query is None
        assert fragment is None

    def test_can_parse_uri_without_scheme_but_with_port(self):
        scheme, authority, path, query, fragment = parse_uri(b"//example.com:8080")
        assert scheme is None
        assert authority == b"example.com:8080"
        assert path == b""
        assert query is None
        assert fragment is None

    def test_can_parse_simple_uri(self):
        scheme, authority, path, query, fragment = parse_uri(b"foo://example.com")
        assert scheme == b"foo"
        assert authority == b"example.com"
        assert path == b""
        assert query is None
        assert fragment is None

    def test_can_parse_uri_with_root_path(self):
        scheme, authority, path, query, fragment = parse_uri(b"foo://example.com/")
        assert scheme == b"foo"
        assert authority == b"example.com"
        assert path == b"/"
        assert query is None
        assert fragment is None

    def test_can_parse_full_uri(self):
        scheme, authority, path, query, fragment = parse_uri(b"foo://bob@somewhere@example.com:8042"
                                                             b"/over/there?name=ferret#nose")
        assert scheme == b"foo"
        assert authority == b"bob@somewhere@example.com:8042"
        assert path == b"/over/there"
        assert query == b"name=ferret"
        assert fragment == b"nose"
        

class BuildURITestCase(TestCase):
    """
    """

    def test_can_build_empty_uri(self):
        built = build_uri()
        assert built is b""

    def test_can_build_uri_from_string(self):
        built = build_uri(uri=b"foo://example.com/")
        assert built == b"foo://example.com/"

    def test_can_build_uri_from_hierarchical_part(self):
        built = build_uri(hierarchical_part=b"//example.com/")
        assert built == b"//example.com/"

    def test_can_build_uri_from_scheme_and_hierarchical_part(self):
        built = build_uri(scheme=b"foo", hierarchical_part=b"//example.com/")
        assert built == b"foo://example.com/"

    def test_can_build_uri_from_scheme_hierarchical_part_and_query(self):
        built = build_uri(scheme=b"foo", hierarchical_part=b"//example.com/", query=b"spam=eggs")
        assert built == b"foo://example.com/?spam=eggs"

    def test_can_build_uri_from_scheme_hierarchical_part_query_and_fragment(self):
        built = build_uri(scheme=b"foo", hierarchical_part=b"//example.com/", query=b"spam=eggs",
                          fragment=b"mustard")
        assert built == b"foo://example.com/?spam=eggs#mustard"

    def test_can_build_uri_from_absolute_path_reference(self):
        built = build_uri(absolute_path_reference=b"/foo/bar?spam=eggs#mustard")
        assert built == b"/foo/bar?spam=eggs#mustard"

    def test_can_build_uri_from_authority_and_absolute_path_reference(self):
        built = build_uri(authority=b"bob@example.com:9999",
                          absolute_path_reference=b"/foo/bar?spam=eggs#mustard")
        assert built == b"//bob@example.com:9999/foo/bar?spam=eggs#mustard"

    def test_can_build_uri_from_scheme_host_and_path(self):
        built = build_uri(scheme=b"http", host=b"example.com", path=b"/foo/bar")
        assert built == b"http://example.com/foo/bar"

    def test_can_build_uri_from_scheme_and_host_port(self):
        built = build_uri(scheme=b"http", host_port=b"example.com:3456")
        assert built == b"http://example.com:3456"

    def test_can_build_uri_from_scheme_authority_and_host_port(self):
        built = build_uri(scheme=b"http", authority=b"bob@example.net:4567",
                          host_port=b"example.com:3456")
        assert built == b"http://bob@example.com:3456"

    def test_can_build_uri_from_scheme_user_info_and_host_port(self):
        built = build_uri(scheme=b"http", user_info=b"bob", host_port=b"example.com:3456")
        assert built == b"http://bob@example.com:3456"

    def test_can_build_uri_from_scheme_user_info_and_path(self):
        built = build_uri(scheme=b"http", user_info=b"bob", path=b"/foo")
        assert built == b"http://bob@/foo"

    def test_can_build_uri_from_scheme_authority_and_host(self):
        built = build_uri(scheme=b"http", authority=b"bob@example.net", host=b"example.com")
        assert built == b"http://bob@example.com"

    def test_can_build_uri_from_scheme_authority_and_port(self):
        built = build_uri(scheme=b"http", authority=b"bob@example.com", port=3456)
        assert built == b"http://bob@example.com:3456"

    def test_can_build_uri_from_scheme_port_and_path(self):
        built = build_uri(scheme=b"http", port=3456, path=b"/foo")
        assert built == b"http://:3456/foo"


class ResolveURITestCase(TestCase):
    """ RFC 3986, section 5.4.
    """

    base_uri = b"http://a/b/c/d;p?q"

    def resolve_references(self, references, strict=True):
        for reference, target in references.items():
            print(reference, "->", target)
            resolved = resolve_uri(self.base_uri, reference, strict)
            assert resolved == target

    def test_normal_examples(self):
        """ 5.4.1.  Normal Examples
        """

        self.resolve_references({
            b"g:h": b"g:h",
            b"g": b"http://a/b/c/g",
            b"./g": b"http://a/b/c/g",
            b"g/": b"http://a/b/c/g/",
            b"/g": b"http://a/g",
            b"//g": b"http://g",
            b"?y": b"http://a/b/c/d;p?y",
            b"g?y": b"http://a/b/c/g?y",
            b"#s": b"http://a/b/c/d;p?q#s",
            b"g#s": b"http://a/b/c/g#s",
            b"g?y#s": b"http://a/b/c/g?y#s",
            b";x": b"http://a/b/c/;x",
            b"g;x": b"http://a/b/c/g;x",
            b"g;x?y#s": b"http://a/b/c/g;x?y#s",
            b"": b"http://a/b/c/d;p?q",
            b".": b"http://a/b/c/",
            b"./": b"http://a/b/c/",
            b"..": b"http://a/b/",
            b"../": b"http://a/b/",
            b"../g": b"http://a/b/g",
            b"../..": b"http://a/",
            b"../../": b"http://a/",
            b"../../g": b"http://a/g",
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
            b"../../../g": b"http://a/g",
            b"../../../../g": b"http://a/g",
        })

        # Similarly, parsers must remove the dot-segments "." and ".." when
        # they are complete components of a path, but not when they are only
        # part of a segment.
        self.resolve_references({
            b"/./g": b"http://a/g",
            b"/../g": b"http://a/g",
            b"g.": b"http://a/b/c/g.",
            b".g": b"http://a/b/c/.g",
            b"g..": b"http://a/b/c/g..",
            b"..g": b"http://a/b/c/..g",
        })

        # Less likely are cases where the relative reference uses unnecessary
        # or nonsensical forms of the "." and ".." complete path segments.
        self.resolve_references({
            b"./../g": b"http://a/b/g",
            b"./g/.": b"http://a/b/c/g/",
            b"g/./h": b"http://a/b/c/g/h",
            b"g/../h": b"http://a/b/c/h",
            b"g;x=1/./y": b"http://a/b/c/g;x=1/y",
            b"g;x=1/../y": b"http://a/b/c/y",
        })

        # Some applications fail to separate the reference's query and/or
        # fragment components from the path component before merging it with
        # the base path and removing dot-segments.  This error is rarely
        # noticed, as typical usage of a fragment never includes the hierarchy
        # ("/") character and the query component is not normally used within
        # relative references.
        self.resolve_references({
            b"g?y/./x": b"http://a/b/c/g?y/./x",
            b"g?y/../x": b"http://a/b/c/g?y/../x",
            b"g#s/./x": b"http://a/b/c/g#s/./x",
            b"g#s/../x": b"http://a/b/c/g#s/../x",
        })

        # Some parsers allow the scheme name to be present in a relative
        # reference if it is the same as the base URI scheme.  This is
        # considered to be a loophole in prior specifications of partial URI
        # [RFC1630].  Its use should be avoided but is allowed for backward
        # compatibility.
        #
        # for strict parsers:
        self.resolve_references({b"http:g": b"http:g"}, strict=True)
        #
        # for backward compatibility:
        self.resolve_references({b"http:g": b"http://a/b/c/g"}, strict=False)

    def test_can_resolve_from_empty_path(self):
        base = b"http://example.com"
        uri = resolve_uri(base, b"foo")
        assert uri == b"http://example.com/foo"

    def test_can_resolve_from_empty_uri(self):
        base = b""
        uri = resolve_uri(base, b"foo")
        assert uri == b"foo"

    def test_resolving_when_reference_is_none_returns_none(self):
        base = b"http://example.com"
        uri = resolve_uri(base, None)
        assert uri is None


class ParseAuthorityTestCase(TestCase):
    """
    """

    def test_can_parse_none_authority(self):
        user_info, host, port = parse_authority(None)
        assert user_info is None
        assert host is None
        assert port is None

    def test_can_parse_empty_authority(self):
        user_info, host, port = parse_authority(b"")
        assert user_info is None
        assert host == b""
        assert port is None

    def test_can_parse_host_authority(self):
        user_info, host, port = parse_authority(b"example.com")
        assert user_info is None
        assert host == b"example.com"
        assert port is None

    def test_can_parse_host_port_authority(self):
        user_info, host, port = parse_authority(b"example.com:6789")
        assert user_info is None
        assert host == b"example.com"
        assert port == 6789

    def test_can_parse_user_host_authority(self):
        user_info, host, port = parse_authority(b"bob@example.com")
        assert user_info == b"bob"
        assert host == b"example.com"
        assert port is None

    def test_can_parse_email_user_host_authority(self):
        user_info, host, port = parse_authority(b"bob@example.com@example.com")
        assert user_info == b"bob@example.com"
        assert host == b"example.com"
        assert port is None

    def test_can_parse_full_authority(self):
        user_info, host, port = parse_authority(b"bob@example.com:6789")
        assert user_info == b"bob"
        assert host == b"example.com"
        assert port == 6789


class BuildAuthorityTestCase(TestCase):

    pass  # TODO


class ParsePathTestCase(TestCase):

    def test_can_parse_none_path(self):
        path = parse_path(None)
        assert path is None

    def test_can_parse_empty_path(self):
        path = parse_path(b"")
        assert path == [""]

    def test_can_parse_absolute_path(self):
        path = parse_path(b"/foo/bar")
        assert path == ["", "foo", "bar"]

    def test_can_parse_relative_path(self):
        path = parse_path(b"foo/bar")
        assert path == ["foo", "bar"]

    def test_can_parse_path_with_encoded_slash(self):
        path = parse_path(b"/foo/bar%2Fbaz")
        assert path == ["", "foo", "bar/baz"]


class BuildPathTestCase(TestCase):

    pass  # TODO


class RemoveDotSegmentsTestCase(TestCase):

    def test_can_remove_dot_segments_pattern_1(self):
        path_in = b"/a/b/c/./../../g"
        path_out = remove_dot_segments(path_in)
        assert path_out == b"/a/g"

    def test_can_remove_dot_segments_pattern_2(self):
        path_in = b"mid/content=5/../6"
        path_out = remove_dot_segments(path_in)
        assert path_out == b"mid/6"

    def test_can_remove_dot_segments_when_single_dot(self):
        path_in = b"."
        path_out = remove_dot_segments(path_in)
        assert path_out == b""

    def test_can_remove_dot_segments_when_double_dot(self):
        path_in = b".."
        path_out = remove_dot_segments(path_in)
        assert path_out == b""

    def test_can_remove_dot_segments_when_starts_with_single_dot(self):
        path_in = b"./a"
        path_out = remove_dot_segments(path_in)
        assert path_out == b"a"

    def test_can_remove_dot_segments_when_starts_with_double_dot(self):
        path_in = b"../a"
        path_out = remove_dot_segments(path_in)
        assert path_out == b"a"


class ParseParametersTestCase(TestCase):

    def test_can_parse_none_query(self):
        parsed = parse_parameters(None)
        assert parsed is None

    def test_can_parse_empty_query(self):
        parsed = parse_parameters(b"")
        assert parsed == []

    def test_can_parse_value_only_query(self):
        parsed = parse_parameters(b"foo")
        assert parsed == [(None, "foo")]

    def test_can_parse_key_value_query(self):
        parsed = parse_parameters(b"foo=bar")
        assert parsed == [("foo", "bar")]

    def test_can_parse_multi_key_value_query(self):
        parsed = parse_parameters(b"foo=bar&spam=eggs")
        assert parsed == [("foo", "bar"), ("spam", "eggs")]

    def test_can_parse_mixed_query(self):
        parsed = parse_parameters(b"foo&spam=eggs")
        assert parsed == [(None, "foo"), ("spam", "eggs")]

    def test_can_parse_repeated_keys(self):
        parsed = parse_parameters(b"foo=bar&foo=baz&spam=eggs")
        assert parsed == [("foo", "bar"), ("foo", "baz"), ("spam", "eggs")]

    def test_can_handle_percent_decoding_while_parsing(self):
        parsed = parse_parameters(b"ampersand=%26&equals=%3D")
        assert parsed == [("ampersand", "&"), ("equals", "=")]

    def test_can_handle_alternative_separators(self):
        parsed = parse_parameters(b"3:%33;S:%53", item_separator=b";", key_separator=b":")
        assert parsed == [("3", "3"), ("S", "S")]

    def test_can_parse_path_segment_with_parameters(self):
        path_segment = b"name;version=1.2"
        parameters = parse_parameters(path_segment, item_separator=b";")
        assert parameters == [(None, "name"), ("version", "1.2")]


class ExpandURITestCase(TestCase):

    def test_expansion_with_no_variables(self):
        template = b"{}"
        uri = expand_uri(template, {})
        assert uri == b""

    def assert_expansions(self, expansions):
        variables = {
            b"count": (b"one", b"two", b"three"),
            b"dom": (b"example", b"com"),
            b"dub": b"me/too",
            b"hello": b"Hello World!",
            b"half": b"50%",
            b"var": b"value",
            b"who": b"fred",
            b"base": b"http://example.com/home/",
            b"path": b"/foo/bar",
            b"list": (b"red", b"green", b"blue"),
            b"keys": OrderedDict([(b"semi", b";"), (b"dot", b"."), (b"comma", b",")]),
            b"v": b"6",
            b"x": b"1024",
            b"y": b"768",
            b"empty": b"",
            b"empty_keys": dict([]),
            b"undef": None,
        }
        for template, expansion in expansions.items():
            print(template, "->", expansion)
            uri = expand_uri(template, variables)
            assert uri == expansion

    def test_empty_expansion(self):
        self.assert_expansions({
            None: None,
            b"": b"",
        })

    def test_can_expand_simple_strings(self):
        self.assert_expansions({
            b"{var}": b"value",
            b"{hello}": b"Hello%20World%21",
            b"{half}": b"50%25",
            b"O{empty}X": b"OX",
            b"O{undef}X": b"OX",
            b"{x,y}": b"1024,768",
            b"{x,hello,y}": b"1024,Hello%20World%21,768",
            b"?{x,empty}": b"?1024,",
            b"?{x,undef}": b"?1024",
            b"?{undef,y}": b"?768",
            b"{var:3}": b"val",
            b"{var:30}": b"value",
            b"{list}": b"red,green,blue",
            b"{list*}": b"red,green,blue",
            b"{keys}": b"semi,%3B,dot,.,comma,%2C",
            b"{keys*}": b"semi=%3B,dot=.,comma=%2C",
        })

    def test_can_expand_reserved_strings(self):
        self.assert_expansions({
            b"{+var}": b"value",
            b"{+hello}": b"Hello%20World!",
            b"{+half}": b"50%25",
            b"{base}index": b"http%3A%2F%2Fexample.com%2Fhome%2Findex",
            b"{+base}index": b"http://example.com/home/index",
            b"O{+empty}X": b"OX",
            b"O{+undef}X": b"OX",
            b"{+path}/here": b"/foo/bar/here",
            b"here?ref={+path}": b"here?ref=/foo/bar",
            b"up{+path}{var}/here": b"up/foo/barvalue/here",
            b"{+x,hello,y}": b"1024,Hello%20World!,768",
            b"{+path,x}/here": b"/foo/bar,1024/here",
            b"{+path:6}/here": b"/foo/b/here",
            b"{+list}": b"red,green,blue",
            b"{+list*}": b"red,green,blue",
            b"{+keys}": b"semi,;,dot,.,comma,,",
            b"{+keys*}": b"semi=;,dot=.,comma=,",
        })

    def test_can_expand_fragments(self):
        self.assert_expansions({
            b"{#var}": b"#value",
            b"{#hello}": b"#Hello%20World!",
            b"{#half}": b"#50%25",
            b"foo{#empty}": b"foo#",
            b"foo{#undef}": b"foo",
            b"{#x,hello,y}": b"#1024,Hello%20World!,768",
            b"{#path,x}/here": b"#/foo/bar,1024/here",
            b"{#path:6}/here": b"#/foo/b/here",
            b"{#list}": b"#red,green,blue",
            b"{#list*}": b"#red,green,blue",
            b"{#keys}": b"#semi,;,dot,.,comma,,",
            b"{#keys*}": b"#semi=;,dot=.,comma=,",
        })

    def test_can_expand_labels(self):
        self.assert_expansions({
            b"{.who}": b".fred",
            b"{.who,who}": b".fred.fred",
            b"{.half,who}": b".50%25.fred",
            b"www{.dom*}": b"www.example.com",
            b"X{.var}": b"X.value",
            b"X{.empty}": b"X.",
            b"X{.undef}": b"X",
            b"X{.var:3}": b"X.val",
            b"X{.list}": b"X.red,green,blue",
            b"X{.list*}": b"X.red.green.blue",
            b"X{.keys}": b"X.semi,%3B,dot,.,comma,%2C",
            b"X{.keys*}": b"X.semi=%3B.dot=..comma=%2C",
            b"X{.empty_keys}": b"X",
            b"X{.empty_keys*}": b"X",
        })

    def test_can_expand_path_segments(self):
        self.assert_expansions({
            b"{/who}": b"/fred",
            b"{/who,who}": b"/fred/fred",
            b"{/half,who}": b"/50%25/fred",
            b"{/who,dub}": b"/fred/me%2Ftoo",
            b"{/var}": b"/value",
            b"{/var,empty}": b"/value/",
            b"{/var,undef}": b"/value",
            b"{/var,x}/here": b"/value/1024/here",
            b"{/var:1,var}": b"/v/value",
            b"{/list}": b"/red,green,blue",
            b"{/list*}": b"/red/green/blue",
            b"{/list*,path:4}": b"/red/green/blue/%2Ffoo",
            b"{/keys}": b"/semi,%3B,dot,.,comma,%2C",
            b"{/keys*}": b"/semi=%3B/dot=./comma=%2C",
        })

    def test_can_expand_path_parameters(self):
        self.assert_expansions({
            b"{;who}": b";who=fred",
            b"{;half}": b";half=50%25",
            b"{;empty}": b";empty",
            b"{;v,empty,who}": b";v=6;empty;who=fred",
            b"{;v,bar,who}": b";v=6;who=fred",
            b"{;x,y}": b";x=1024;y=768",
            b"{;x,y,empty}": b";x=1024;y=768;empty",
            b"{;x,y,undef}": b";x=1024;y=768",
            b"{;hello:5}": b";hello=Hello",
            b"{;list}": b";list=red,green,blue",
            b"{;list*}": b";list=red;list=green;list=blue",
            b"{;keys}": b";keys=semi,%3B,dot,.,comma,%2C",
            b"{;keys*}": b";semi=%3B;dot=.;comma=%2C",
        })

    def test_can_expand_form_queries(self):
        self.assert_expansions({
            b"{?who}": b"?who=fred",
            b"{?half}": b"?half=50%25",
            b"{?x,y}": b"?x=1024&y=768",
            b"{?x,y,empty}": b"?x=1024&y=768&empty=",
            b"{?x,y,undef}": b"?x=1024&y=768",
            b"{?var:3}": b"?var=val",
            b"{?list}": b"?list=red,green,blue",
            b"{?list*}": b"?list=red&list=green&list=blue",
            b"{?keys}": b"?keys=semi,%3B,dot,.,comma,%2C",
            b"{?keys*}": b"?semi=%3B&dot=.&comma=%2C",
        })

    def test_can_expand_form_query_continuations(self):
        self.assert_expansions({
            b"{&who}": b"&who=fred",
            b"{&half}": b"&half=50%25",
            b"?fixed=yes{&x}": b"?fixed=yes&x=1024",
            b"{&x,y,empty}": b"&x=1024&y=768&empty=",
            b"{&x,y,undef}": b"&x=1024&y=768",
            b"{&var:3}": b"&var=val",
            b"{&list}": b"&list=red,green,blue",
            b"{&list*}": b"&list=red&list=green&list=blue",
            b"{&keys}": b"&keys=semi,%3B,dot,.,comma,%2C",
            b"{&keys*}": b"&semi=%3B&dot=.&comma=%2C",
        })
