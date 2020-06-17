# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>

import unittest
import os
import re

import dkim


def read_test_data(filename):
    """Get the content of the given test data file.

    The files live in dkim/tests/data.
    """
    path = os.path.join(os.path.dirname(__file__), 'data', filename)
    with open(path, 'rb') as f:
        return f.read()


class TestAlignment(unittest.TestCase):

    def test_strict(self):
        self.assertTrue(dkim.check_alignment(b"foo@example.com", b"example.com"))

    def test_relaxed(self):
        self.assertTrue(dkim.check_alignment(b"foo@test.example.com", b"example.com"))

    def test_bad_suffix(self):
        self.assertFalse(dkim.check_alignment(b"foo@example.com", b"ample.com"))


class TestDkimAlignment(unittest.TestCase):

    def setUp(self):
        self.message = read_test_data("test.message")
        self.key = read_test_data("test.private")

    def dnsfunc(self, domain, timeout=5):
        _dns_responses = {
            'test._domainkey.attacker.com.': read_test_data("test.txt"),
            'test2._domainkey.attacker.com.': read_test_data("test.txt"),
            'test._domainkey.example.com.': read_test_data("test.txt"),
        }
        try:
            domain = domain.decode('ascii')
        except UnicodeDecodeError:
            return None
        self.assertTrue(domain in _dns_responses, domain)
        return _dns_responses[domain]

    def dnsfunc2(self, domain, timeout=5):
        _dns_responses = {
            'test._domainkey.attacker.com.': read_test_data("test.txt"),
            'test2._domainkey.attacker.com.': read_test_data("test.txt"),
            'test._domainkey.example.com.': read_test_data("test_bad.txt"),
        }
        try:
            domain = domain.decode('ascii')
        except UnicodeDecodeError:
            return None
        self.assertTrue(domain in _dns_responses, domain)
        return _dns_responses[domain]

    def test_malaligned(self):
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                sig = dkim.sign(
                    self.message, b"test", b"attacker.com", self.key,
                    canonicalize=(header_algo, body_algo))
                verify_res = dkim.verify(sig + self.message, dnsfunc=self.dnsfunc)
                self.assertTrue(verify_res)
                full_verify_res = dkim.full_verify(sig + self.message, dnsfunc=self.dnsfunc)
                self.assertFalse(full_verify_res)

    def test_aligned(self):
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                sig = dkim.sign(
                    self.message, b"test", b"example.com", self.key,
                    canonicalize=(header_algo, body_algo))
                res = dkim.full_verify(sig + self.message, dnsfunc=self.dnsfunc)
                self.assertTrue(res)

    def test_multi_signature(self):
        # (malaligned, good signature) + (aligned, good signature)
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                first_sig = dkim.sign(
                    self.message, b"test", b"example.com", self.key,
                    canonicalize=(header_algo, body_algo))
                second_sig = dkim.sign(
                    first_sig + self.message, b"test", b"attacker.com", self.key,
                    canonicalize=(header_algo, body_algo))
                res = dkim.full_verify(second_sig + first_sig + self.message,
                                       dnsfunc=self.dnsfunc)
                self.assertTrue(res)

        # (aligned, good signature) + (malaligned, good signature)
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                first_sig = dkim.sign(
                    self.message, b"test", b"attacker.com", self.key,
                    canonicalize=(header_algo, body_algo))
                second_sig = dkim.sign(
                    first_sig + self.message, b"test", b"example.com", self.key,
                    canonicalize=(header_algo, body_algo))
                res = dkim.full_verify(second_sig + first_sig + self.message,
                                       dnsfunc=self.dnsfunc)
                self.assertTrue(res)

    def test_multi_bad_signature(self):
        # (malaligned, good signature) + (malaligned, good signature)
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                first_sig = dkim.sign(
                    self.message, b"test", b"attacker.com", self.key,
                    canonicalize=(header_algo, body_algo))
                second_sig = dkim.sign(
                    first_sig + self.message, b"test2", b"attacker.com", self.key,
                    canonicalize=(header_algo, body_algo))
                res = dkim.full_verify(second_sig + first_sig + self.message,
                                       dnsfunc=self.dnsfunc)
                self.assertFalse(res)

        # (malaligned, good signature) + (aligned, bad signature)
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                first_sig = dkim.sign(
                    self.message, b"test", b"example.com", self.key,
                    canonicalize=(header_algo, body_algo))
                second_sig = dkim.sign(
                    first_sig + self.message, b"test", b"attacker.com", self.key,
                    canonicalize=(header_algo, body_algo))
                res = dkim.full_verify(second_sig + first_sig + self.message,
                                       dnsfunc=self.dnsfunc2)
                self.assertFalse(res)

        # (aligned, bad signature) + (malaligned, good signature)
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                first_sig = dkim.sign(
                    self.message, b"test", b"attacker.com", self.key,
                    canonicalize=(header_algo, body_algo))
                second_sig = dkim.sign(
                    first_sig + self.message, b"test", b"example.com", self.key,
                    canonicalize=(header_algo, body_algo))
                res = dkim.full_verify(second_sig + first_sig + self.message,
                                       dnsfunc=self.dnsfunc2)
                self.assertFalse(res)


class TestFromHeader(unittest.TestCase):

    def setUp(self):
        self.message = read_test_data("test.message")
        self.key = read_test_data("test.private")

    def dnsfunc(self, domain, timeout=5):
        _dns_responses = {
            'test._domainkey.example.com.': read_test_data("test.txt"),
        }
        try:
            domain = domain.decode('ascii')
        except UnicodeDecodeError:
            return None
        self.assertTrue(domain in _dns_responses, domain)
        return _dns_responses[domain]

    def test_multiple_from_headers(self):
        message = b'From: Bad\n' + self.message
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                sig = dkim.sign(
                    message, b"test", b"example.com", self.key,
                    canonicalize=(header_algo, body_algo))
                self.assertFalse(dkim.full_verify(sig + message, dnsfunc=self.dnsfunc))

    def test_multiple_from_address(self):
        message = re.sub(br'From:.*?\n',
                         b'From: Test User <test@example.com>, Test User 2 <test2@example.com>\n',
                         self.message)
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                sig = dkim.sign(
                    message, b"test", b"example.com", self.key,
                    canonicalize=(header_algo, body_algo))
                self.assertFalse(dkim.full_verify(sig + message, dnsfunc=self.dnsfunc))


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
