# uncompyle6 version 2.13.2
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.6.3 (default, Oct  3 2017, 21:16:13)
# [GCC 7.2.0]
# Embedded file name: /home/user/_my/code/mailencrypt-related/py-autocrypt/core/autocrypt/storage_orm.py
# Compiled at: 2017-11-08 17:34:34
# Size of source mod 2**32: 2361 bytes
import enum
import logging
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Enum, LargeBinary, ForeignKey
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import relationship
from .constants import NOPREFERENCE, MUTUAL
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)
Base = declarative_base()

class PE_ENUM(enum.Enum):
    none = None
    nopreference = NOPREFERENCE
    mutual = MUTUAL


class Account(Base):
    __tablename__ = 'ac_account'
    id = Column(primary_key=Integer,)
    enabled = Column(Boolean)
    pe = Column(Enum(PE_ENUM))
    skey = Column(LargeBinary())
    pkey = Column(LargeBinary())
    accounts = relationship(backref='AccountList',)


class Peer(Base):
    __tablename__ = 'ac_peer'
    id = Column(primary_key=Integer,)
    pe = Enum(PE_ENUM)
    pkey = LargeBinary()
    ls = DateTime(timezone=True,)
    ats = DateTime(timezone=True,)
    gpk = LargeBinary()
    gts = DateTime(timezone=True,)
    peers = relationship(backref='PeerList',)


class AccountList(Base):
    __tablename__ = 'ac_accountlist'
    id = Column(primary_key=Integer,)
    addr = Column(String(254))
    account_id = Column(Integer, ForeignKey('ac_account.id'))
    profiles = relationship(backref='Profile',)


class PeerList(Base):
    __tablename__ = 'ac_peerlist'
    id = Column(primary_key=Integer,)
    addr = Column(String(254))
    peer_id = Column(Integer, ForeignKey('ac_peer.id'))
    profiles = relationship(backref='Profile',)


class Profile(Base):
    __tablename__ = 'ac_profile'
    id = Column(primary_key=Integer,)
    peers_id = Column(Integer, ForeignKey('ac_peerlist.id'))
    accounts_id = Column(Integer, ForeignKey('ac_accountlist.id'))
