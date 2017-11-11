# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

""" .
"""

from __future__ import unicode_literals

import enum
import logging
import sqlite3

import attr

# from attr.validators import instance_of
from base64 import b64encode
from datetime import datetime
from email.header import Header
from email.mime.text import MIMEText

from .constants import (NOPREFERENCE, AC, MUTUAL, PE_HEADER_TYPES, ADDR,
                        KEYDATA, PREFER_ENCRYPT, PEER_STATE_TYPES,
                        ACCOUNT_PE_TYPES)


class Internal(object):
    pass

def db_create(sqlitepath):
    conn = sqlite3.connect(sqlitepath)
    c = conn.cursor()
    c.execute("CREATE TABLE account (addr varchar(250) PRIMARY KEY ASC, "
              "kd text, pe varchar(250))")
    c.execute("CREATE TABLE peer (addr varchar(250) PRIMARY KEY ASC, "
              "ls text, lsa text, pe varchar(250))")
    c.execute("CREATE TABLE peers (id INTEGER PRIMARY KEY ASC, "
              "addr varchar(250))")
    c.execute("CREATE TABLE accounts (id INTEGER PRIMARY KEY ASC, "
              "addr varchar(250))")
    conn.commit()
    conn.close()


def db_insert(sqlitepath):
    conn = sqlite3.connect(sqlitepath)
    c = conn.cursor()
    # INSERT INTO account (addr, pe, pk) values ('', '', '');
    c.execute("INSERT INTO account (addr, kd, pe)", attr.astuple(p))
    c.execute("INSERT INTO peer VALUES (addr, ls, lsa, pe)", attr.astuple(p))
    c.execute("INSERT INTO peers VALUES (addr, kd, pe)", attr.astuple(p))
    c.execute("INSERT INTO accounts VALUES (addr, ls, lsa, pe)", attr.astuple(p))

    conn.commit()
    conn.close()

@attr.s
class Account(object):
    """ .

    > a = Account('alice@autocrypt.example', 'foo', 'bar', MUTUAL)
    > print(a)
    addr=alice@autocrypt.example

    """
    # def __init__(self, addr, secret_key, public_key, prefer_encrypt):
    #     self.addr = addr
    #     self.secret_key = secret_key
    #     self.public_key = public_key
    #     # self.keyhandle = keyhandle or ""
    #     self.prefer_encrypt = prefer_encrypt
    addr = attr.ib(default="", validator=attr.validators.instance_of(str))
    pr = attr.ib(default=None,
                 validator=attr.validators.in_(PE_HEADER_TYPES))
    pk = attr.ib(default='',
                 validator=attr.validators.instance_of(str))
    sk = attr.ib(default='',
                 validator=attr.validators.instance_of(str))

    def serialize():
        pass

    def __str__(self):
        return "addr={}".format(self.addr)



@attr.s
class Peer(object):
    """ . """
    # def __init__(self, addr, last_seen, last_seen_ac, state):
    #     self.addr = addr
    #     self.last_seen = last_seen
    #     self.last_seen_ac = last_seen_ac
    #     self.state = state
    addr = attr.ib(default="", validator=attr.validators.instance_of(str))
    ls = attr.ib(default=datetime.now(),
                 validator=attr.validators.instance_of(datetime))
    lsa = attr.ib(default=datetime.now(),
                  validator=attr.validators.instance_of(datetime))
    state = attr.ib(default=NOPREFERENCE,
                    validator=attr.validators.in_(PEER_STATE_TYPES))

    def serialize():
        pass

    def __str__(self):
        return "addr={}".format(self.addr)
