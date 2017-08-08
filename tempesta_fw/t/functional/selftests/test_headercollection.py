from __future__ import print_function
import unittest
from StringIO import StringIO
from helpers import deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestHeaderCollection(unittest.TestCase):
    def setUp(self):
        self.headers = deproxy.HeaderCollection()

    def test_length(self):
        self.assertEqual(len(self.headers), 0)
        self.headers.add('Name', 'Value')
        self.assertEqual(len(self.headers), 1)

    def test_add(self):
        self.headers.add('Name', 'Value')
        self.assertIn('name', self.headers)
        self.assertIn('Name', self.headers)

    def test_find_all(self):
        self.headers.add('A', 'qwerty')
        self.headers.add('B', 'asdf')
        self.headers.add('C', 'zxcv')
        self.headers.add('A', 'uiop')
        self.headers.add('A', 'jkl;')

        result = [value for value in self.headers.find_all('A')]
        self.assertEqual(result, ['qwerty', 'uiop', 'jkl;'])

        result = [value for value in self.headers.find_all('a')]
        self.assertEqual(result, ['qwerty', 'uiop', 'jkl;'])

    def test_bracket_case(self):
        self.headers.add('Name', 'Value')
        self.assertEqual(self.headers['name'], 'Value')
        self.assertEqual(self.headers['Name'], 'Value')

    def test_get(self):
        self.headers.add('Name', 'Value')

        self.assertEqual(self.headers.get('Name'), 'Value')
        self.assertEqual(self.headers.get('name'), 'Value')
        self.assertIsNone(self.headers.get('asdf'))
        self.assertEqual(self.headers.get('name', default='zxcv'), 'Value')
        self.assertEqual(self.headers.get('asdf', default='zxcv'), 'zxcv')

    def test_keys(self):
        self.headers.add('A', 'qwerty')
        self.headers.add('B', 'asdf')
        self.headers.add('C', 'zxcv')
        self.headers.add('A', 'uiop')
        self.headers.add('A', 'jkl;')

        self.assertEqual(set(self.headers.keys()), set(['a', 'b', 'c']))

    def test_from_stream(self):
        test_headers = [('User-Agent', 'Wget/1.13.4 (linux-gnu)'),
                        ('Accept', '*/*'),
                        ('Host', '   localhost  '),
                        ('Connection', ' Keep-Alive'),
                        ('X-Custom-Hdr', 'custom header values'),
                        ('x-custom-hdr', 'custom header values 2'),
                        ('X-Forwarded-For', '127.0.0.1, example.com'),
                        ('Content-Type', 'text/html; charset=iso-8859-1'),
                        ('Cache-Control', 'max-age=1, no-store, min-fresh=30'),
                        ('Pragma', 'no-cache, fooo'),
                        ('Transfer-Encoding', 'compress, gzip, chunked'),
                        ('Cookie', 'session=42; theme=dark')]
        text = '\r\n'.join(['%s: %s' % header for header in test_headers] +
                           ['\r\n'])

        stream = StringIO(text)
        parsed_headers = deproxy.HeaderCollection.from_stream(stream)
        self.assertEqual(len(parsed_headers), len(test_headers))

        for header, value in test_headers:
            if header.lower() == 'x-custom-hdr':
                continue
            self.assertEqual(parsed_headers[header], value.strip())
            self.assertEqual(parsed_headers[header.lower()], value.strip())

        for header in ['X-Custom-Hdr', 'x-custom-hdr']:
            self.assertEqual(
                set(parsed_headers.find_all(header)),
                set(['custom header values', 'custom header values 2']))

        expect_headers = [(header.strip(), value.strip())
                          for (header, value) in test_headers]
        self.assertEqual(expect_headers, parsed_headers.items())

    def test_is_equal(self):
        self.headers.add('A', 'qwerty')
        self.headers.add('B', 'asdf')
        self.headers.add('C', 'zxcv')
        self.headers.add('A', 'uiop')
        self.headers.add('A', 'jkl;')

        reorderd = deproxy.HeaderCollection()
        reorderd.add('C', 'zxcv')
        reorderd.add('A', 'qwerty')
        reorderd.add('A', 'uiop')
        reorderd.add('A', 'jkl;')
        reorderd.add('B', 'asdf')
        self.assertTrue(self.headers == reorderd)
        self.assertFalse(self.headers != reorderd)

        same_keys_reorderd = deproxy.HeaderCollection()
        same_keys_reorderd.add('C', 'zxcv')
        same_keys_reorderd.add('A', 'uiop')
        same_keys_reorderd.add('A', 'jkl;')
        same_keys_reorderd.add('A', 'qwerty')
        same_keys_reorderd.add('B', 'asdf')
        self.assertTrue(self.headers != same_keys_reorderd)
        self.assertFalse(self.headers == same_keys_reorderd)

        other = deproxy.HeaderCollection()
        other.add('C', 'zxcv')
        other.add('A', 'uiop')
        other.add('A', 'jkl;')
        self.assertTrue(self.headers != other)
        self.assertFalse(self.headers == other)

        same_keys = deproxy.HeaderCollection()
        same_keys.add('C', 'zxcv')
        same_keys.add('B', 'uiop')
        same_keys.add('A', 'jkl;')
        self.assertTrue(self.headers != same_keys)
        self.assertFalse(self.headers == same_keys)

        lowed = deproxy.HeaderCollection()
        lowed.add('c', 'zxcv')
        lowed.add('a', 'qwerty')
        lowed.add('a', 'uiop')
        lowed.add('A', 'jkl;')
        lowed.add('b', 'asdf')
        self.assertTrue(self.headers == lowed)
        self.assertFalse(self.headers != lowed)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
