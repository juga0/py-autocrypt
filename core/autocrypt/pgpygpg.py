# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""PGPYGPG implements GPG operations needed for Autocrypt.
"""
# FIXME: this file should be moved to ../autocrypt/ and possibly
# merged with gpg.py

from __future__ import print_function, unicode_literals
import logging
from distutils.version import LooseVersion as V
import os
import sys
from contextlib import contextmanager
from base64 import b64encode
import tempfile
import re
import getpass
from pgpy import PGPKey, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm, CompressionAlgorithm

PGPY_USAGE = {KeyFlags.Sign}
PGPY_HASHES = [HashAlgorithm.SHA512, HashAlgorithm.SHA256],
PGPY_CIPHERS = [SymmetricKeyAlgorithm.AES256,
                SymmetricKeyAlgorithm.AES192,
                SymmetricKeyAlgorithm.AES128],
PGPY_COMPRESSION = [CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZ2,
                    CompressionAlgorithm.ZIP,
                    CompressionAlgorithm.Uncompressed]

logger = logging.getLogger(__name__)


def key_base64(key):
    """Base 64 representation of key bytes.

    :param key: key (either public or private)
    :type key: PGPKey
    :return: Base 64 representation of key bytes
    :rtype: string

    """
    keybytes = key_bytes(key)
    keybase64 = b64encode(keybytes)
    return keybase64


def key_bytes(key):
    """Key bytes.

    :param key: key (either public or private)
    :type key: PGPKey
    :return: key bytes
    :rtype: string

    """
    if sys.version_info >= (3, 0):
        keybytes = bytes(key)
    else:
        keybytes = key.__bytes__()
    return keybytes


def key_shortid(key):
    return key.fingerprint.replace(' ', '')[:8]


def key_longid(key):
    return key.fingerprint.replace(' ', '')[:16]


def cached_property(f):
    # returns a property definition which lazily computes and
    # caches the result of calling f.  The property also allows
    # setting the value (before or after read).
    def get(self):
        propcache = self.__dict__.setdefault("_property_cache", {})
        key = f.__name__
        try:
            return propcache[key]
        except KeyError:
            x = self._property_cache[key] = f(self)
            return x

    def set(self, val):
        propcache = self.__dict__.setdefault("_property_cache", {})
        propcache[f.__name__] = val
    return property(get, set)


class PGPyGPG(object):
    """ PGPy operations for Autocrypt. """
    key = None

    def __init__(self, homedir=None, gpgpath=None):
        # FIXME: gpgpath is not needed,
        # left for compatibility with BinGPG
        self.homedir = homedir
        self._ensure_init()

    def __str__(self):
        return "PGPyGPG(homedir={homedir!r})".format(
            homedir=self.homedir)

    def _ensure_init(self):
        if self.homedir is None:
            return

        if not os.path.exists(self.homedir):
            # we create the dir if the basedir exists, otherwise we fail
            os.mkdir(self.homedir)
            os.chmod(self.homedir, 0o700)

    def gen_secret_key(self,
                       emailadr='alice@testsuite.autocrypt.org',
                       # uid='alice@testsuite.autocrypt.org',
                       alg_key=PubKeyAlgorithm.RSAEncryptOrSign,
                       alg_subkey=PubKeyAlgorithm.RSAEncryptOrSign,
                       size=2048,
                       add_subkey=True,
                       protected=False):
        # RSAEncrypt is deprecated, therefore using RSAEncryptOrSign
        # also for the subkey
        """Generate PGPKey object.

        :param alg_key: algorithm for primary key
        :param alg_subkey: algorithm for subkey
        :param size: key size
        :param emailadr: e-mail address
        :return: key
        :type alg_key: PubKeyAlgorithm
        :type alg_subkey: PubKeyAlgorithm
        :type size: integer
        :type emailadr: string
        :rtype: PGPKey

        """
        # NOTE: default algorithm was decided to be RSA and size 2048.
        self.key = PGPKey.new(alg_key, size)
        # NOTE: pgpy implements separate attributes for name and e-mail
        # address. Name is mandatory.
        # Here e-mail address is used for the attribute name .
        # If name attribute would be set to empty string
        # and email to the e-mail address, the uid would be
        # ' <e-mail address>', for instance:
        # " <alice@testsuite.autocrypt.org>" - which we do not want.
        uid = PGPUID.new(emailadr)
        logger.debug('uid %s', uid)
        # NOTE: it is needed to specify all arguments in current pgpy version.
        # FIXME: see which defaults we would like here
        self.key.add_uid(uid,
                        #  usage=PGPY_USAGE,
                        #  hashes=PGPY_HASHES,
                        #  ciphers=PGPY_CIPHERS,
                        #  compression=PGPY_COMPRESSION)
                usage={KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA512, HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256,
                         SymmetricKeyAlgorithm.AES192,
                         SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB,
                             CompressionAlgorithm.BZ2,
                             CompressionAlgorithm.ZIP,
                             CompressionAlgorithm.Uncompressed])
        if add_subkey is True:
            subkey = PGPKey.new(alg_subkey, size)
            self.key.add_subkey(subkey,
                                usage={KeyFlags.EncryptCommunications,
                                       KeyFlags.EncryptStorage})
            logger.debug('Created subkey')
        if protected is True:
            passphrase = getpass.getpass()
            self.key.protect(passphrase, SymmetricKeyAlgorithm.AES256,
                             HashAlgorithm.SHA256)
            logger.debug('Key protected')
        keyhandle = key_longid(self.key)
        logger.debug('Created key pair %s', keyhandle)
        return keyhandle
    #
    # def key_shortid(self):
    #     return self.key.fingerprint.replace(' ', '')[:8]
    #
    # def key_longid(self):
    #     return self.key.fingerprint.replace(' ', '')[:16]

    def get_public_keydata(self, keyhandle=None, armor=False,
                           b64=False):
        # FIXME: keyhandle not needed, left for compatibility with
        # BinGPG
        if armor is True:
            keydata = str(self.key.pubkey)
        else:
            keydata = key_bytes(self.key.pubkey)
        if b64 is True:
            keydata = key_base64(self.key.pubkey)
        return keydata

    def get_secret_keydata(self, keyhandle=None, armor=False):
        # FIXME: keyhandle not needed, left for compatibility with
        # BinGPG
        if armor is True:
            keydata = str(self.key)
        else:
            keydata = key_bytes(self.key)
        return keydata

    def encrypt(self, data, recipients):
        # The symmetric cipher should be specified, in case the first
        # preferred cipher is not the same for all recipients' public keys
        cipher = SymmetricKeyAlgorithm.AES256
        sessionkey = cipher.gen_key()
        enc_msg = data
        for r in recipients:
            # rpubkey = None
            enc_msg = self.key.encrypt(enc_msg, cipher=cipher,
                                       sessionkey=sessionkey, user=r)
        # do at least this as soon as possible after encrypting to the
        # final recipient
        del sessionkey
        return enc_msg

    def sign(self, data, keyhandle=None):
        # pubkey = None
        sig_data = self.key.sign(data)
        return str(sig_data)

    def verify(self, data, signature):
        # pubkey = None
        # signature = SignatureVerification()
        ver = self.key.verify(data, signature)
        # key_longid(key)
        return ver

    def decrypt(self, enc_data):
        # out = enc_data.decrypt()
        # args = self._nopassphrase + ["--with-colons", "--decrypt"]
        # out, err = self._gpg_outerr(args, input=enc_data, encoding=None)
        # lines = err.splitlines()
        # pubkey = None
        out = self.key.decrypt(enc_data)
        return out
        # keyinfos = []
        # while lines:
        #     line1 = lines.pop(0)
        #     m = re.match("gpg.*with (\d+)-bit (\w+).*"
        #                  "ID (\w+).*created (.*)", line1)
        #     if m:
        #         bits, keytype, id, date = m.groups()
        #         line2 = lines.pop(0)
        #         if line2.startswith("    "):
        #             uid = line2.strip().strip('"')
        #         keyinfos.append(KeyInfo(keytype, bits, id, uid, date))
        # return out, keyinfos

    def import_keydata(self, keydata):
        key, _ = PGPKey.from_blob(keydata)
        return key_longid(key)


class KeyInfo:
    def __init__(self, type, bits, id, uid, date_created):
        self.type = type
        self.bits = int(bits)
        self.id = id
        self.uids = [uid] if uid else []
        self.date_created = date_created

    def match(self, other_id):
        i = min(len(other_id), len(self.id))
        return self.id[-i:] == other_id[-i:]

    def __str__(self):
        return "KeyInfo(id={id!r}, uids={uids!r}, bits={bits}, type={type})".format(
            **self.__dict__)

    __repr__ = __str__
