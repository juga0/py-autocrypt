# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
"""Tests for PGPyCrypto"""

from __future__ import unicode_literals

import pytest

from autocrypt.storage import Account


class TestStorage:
    def test_account(self, accounts):
        a = Account('me@autocrypt.example')
        accounts[a.addr] = a
        assert accounts['me@autocrypt.example'] == \
            Account(addr='me@autocrypt.example', pr=None, pk='', sk='')

    def test_peer(self, accounts):
        p = Peer('bob@autocrypt.example')
        peers[p.addr] = p
        assert peers['bob@autocrypt.example'] == \
            Peer(addr='bob@autocrypt.example', pr=None, pk='', sk='')

# p = Peer('bob@autocrypt.example')
