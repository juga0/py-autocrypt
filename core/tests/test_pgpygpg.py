# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals

import logging
import os
import pytest
from autocrypt.pgpygpg import PGPyGPG, cached_property


logger = logging.getLogger(__name__)


def test_cached_property_object():
    l = []

    class A(object):
        @cached_property
        def x1(self):
            l.append('x')
            return 1

    a = A()
    assert len(l) == 0
    assert a.x1 == 1
    assert l == ['x']
    assert a.x1 == 1
    assert l == ['x']
    a.x1 = 10
    assert a.x1 == 10
    assert l == ['x']
#
#
# @pytest.mark.parametrize("id1,id2", [
#     ("90123456", "1234567890123456"),
#     ("1234567890123456", "1234567890123456"),
# ])
# def test_keyinfo_match(id1, id2):
#     k = KeyInfo(type="1", bits=2048, id=id1, uid="123",
#                 date_created="Di 21. Feb 10:43:40 CET 2017")
#     assert k.match(id2), k


class TestPGPYGPG:

    def test_gen_key_and_get_public_keydata(self, pgpygpg):
        keyhandle = pgpygpg.gen_secret_key(emailadr="hello@xyz.org")
        logger.debug('keyhandle %s', keyhandle)
        # keydata = pgpygpg.get_secret_keydata(keyhandle)
        keydata = pgpygpg.get_public_keydata(keyhandle)
        logger.debug('keydata %s', keydata)

    def test_gen_key_and_get_secret_keydata(self, pgpygpg):
        keyhandle = pgpygpg.gen_secret_key(emailadr="hello@xyz.org")
        logger.debug('keyhandle %s', keyhandle)
        # keydata = pgpygpg.get_secret_keydata(keyhandle)
        keydata = pgpygpg.get_secret_keydata(keyhandle)
        logger.debug('keydata %s', keydata)

    # def test_list_secret_keyhandles(self, pgpygpg):
    #     #++
    #     keyhandle = pgpygpg.gen_secret_key(emailadr="hello@xyz.org")
    #     l = pgpygpg.list_public_keyinfos(keyhandle)
    #     assert len(l) == 2
    #     assert l[0].id == keyhandle
    #
    #     l = pgpygpg.list_secret_keyinfos(keyhandle)
    #     assert len(l) == 2
    #     assert l[0].match(keyhandle)
    #
    # @pytest.mark.parametrize("armor", [True, False])
    # def test_transfer_key_and_encrypt_decrypt_roundtrip(self, pgpygpg, pgpygpg2, armor):
    #     keyhandle = pgpygpg.gen_secret_key(emailadr="hello@xyz.org")
    #     priv_keydata = pgpygpg.get_secret_keydata(keyhandle=keyhandle, armor=armor)
    #     if armor:
    #         priv_keydata.decode("ascii")
    #     public_keydata = pgpygpg.get_public_keydata(keyhandle=keyhandle, armor=armor)
    #     if armor:
    #         public_keydata.decode("ascii")
    #     keyhandle2 = pgpygpg2.import_keydata(public_keydata)
    #     assert keyhandle2 == keyhandle
    #     out_encrypt = pgpygpg2.encrypt(b"123", recipients=[keyhandle])
    #
    #     out, decrypt_info = pgpygpg.decrypt(out_encrypt)
    #     assert out == b"123"
    #     assert len(decrypt_info) == 1
    #     k = decrypt_info[0]
    #     assert str(k)
    #     assert k.bits == 2048
    #     assert k.type == "RSA"
    #     assert k.date_created
    #     keyinfos = pgpygpg2.list_public_keyinfos(keyhandle)
    #     for keyinfo in keyinfos:
    #         if keyinfo.match(k.id):
    #             break
    #     else:
    #         pytest.fail("decryption key {!r} not found in {}".format(
    #                     k.id, keyinfos))
    #
    def test_gen_key_and_sign_verify(self, pgpygpg):
        keyhandle = pgpygpg.gen_secret_key(emailadr="hello@xyz.org")
        sig = pgpygpg.sign(b"123", keyhandle=keyhandle)
        keyhandle_verified = pgpygpg.verify(data=b'123', signature=sig)
        i = min(len(keyhandle_verified), len(keyhandle))
        assert keyhandle[-i:] == keyhandle_verified[-i:]
