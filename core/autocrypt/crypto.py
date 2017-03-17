# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

# Copyright 2016 juga <juga@riseup.net>

"""Crypto implements GPG operations needed for Autocrypt.
API is copied from bingpg.py
"""

from __future__ import print_function, unicode_literals
import logging
import os
import glob
import sys
from base64 import b64encode
import re
import getpass
from operator import attrgetter
from pgpy import PGPKey, PGPUID, PGPMessage, PGPSignature, PGPKeyring
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm, CompressionAlgorithm

logger = logging.getLogger(__name__)


def key_base64(pgpykey):
    """Base 64 representation of key bytes.

    :param key: key (either public or private)
    :type key: PGPKey
    :return: Base 64 representation of pgpykey bytes
    :rtype: string

    """
    keybytes = key_bytes(pgpykey)
    keybase64 = b64encode(keybytes)
    return keybase64


def key_bytes(pgpykey):
    """Key bytes.

    :param key: key (either public or private)
    :type key: PGPKey
    :return: key bytes
    :rtype: string

    """
    if sys.version_info >= (3, 0):
        keybytes = bytes(pgpykey)
    else:
        keybytes = pgpykey.__bytes__()
    return keybytes


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


class Crypto(object):
    """ GPG operations for Autocrypt using PGPy. """

    def __init__(self, homedir=None):
        self.own_pgpykey = None
        self.publicpgpykeys = []
        self.secretpgpykeys = []
        self.secretpgpykr = None
        self.publicpgpykr = None
        self.pgpydir = homedir
        self._ensure_init()

    def __str__(self):
        return "Crypto(homedir={homedir!r})".format(
            homedir=self.pgpydir)

    def _ensure_init(self):
        if self.pgpydir is None:
            return

        if not os.path.exists(self.pgpydir):
            # we create the dir if the basedir exists, otherwise we fail
            os.mkdir(self.pgpydir)
            os.chmod(self.pgpydir, 0o700)

        self.load_pgpykr()
        # NOTE: this would lose parent and subkeys info.
        # self.load_keys_from_pgpykr()
        self.load_keys_from_pgpyhome()

    def load_pgpykr(self):
        self.publicpgpykr = PGPKeyring(glob.glob(
                                os.path.join(self.pgpydir, '*.asc')))
        logger.debug('publickr fingerprints %s' %
                     self.publicpgpykr.fingerprints())
        self.secretpgpykr = PGPKeyring(glob.glob(
                                os.path.join(self.pgpydir, '*.key')))
        logger.debug('secretpgpykr fingerprints %s' %
                     self.secretpgpykr.fingerprints())

    def load_keys_from_pgpyhome(self):
        pkpaths = glob.glob(os.path.join(self.pgpydir, '*.asc'))
        for pkpath in pkpaths:
            pk, psubkeys = PGPKey.from_file(pkpath)
            self.publicpgpykeys.append(pk)
        skpaths = glob.glob(os.path.join(self.pgpydir, '*.key'))
        for skpath in skpaths:
            sk, ssubkeys = PGPKey.from_file(skpath)
            self.secretpgpykeys.append(sk)

    def load_keys_from_pgpykr(self):
        # NOTE: not using this method
        last_primary = None
        last_non_primary = None
        for fp in self.publicpgpykr.fingerprints():
            with self.publicpgpykr.key(fp) as pk:
                if pk.is_primary:
                    last_primary = pk
                    pk.subkeys.append(last_non_primary)
                    last_non_primary = None
                else:
                    last_non_primary = pk
                    pk.parent = last_primary
                    last_primary = None
                    logger.debug('pk.parent', pk.parent)
                self.publicpgpykeys.append(pk)
        self.publicpgpykeys = sorted(self.publicpgpykeys,
                                     key=attrgetter('fingerprint',
                                                    'is_primary'),
                                     reverse=True)
        logger.debug('public keys %s', self.publicpgpykeys)
        last_primary = None
        last_non_primary = None

        for fp in self.secretpgpykr.fingerprints():
            with self.secretpgpykr.key(fp) as sk:
                if sk.is_primary:
                    last_primary = sk
                    sk.subkeys.append(last_non_primary)
                    last_non_primary = None
                    self.own_pgpykey = sk
                else:
                    last_non_primary = sk
                    sk.parent = last_primary
                    last_primary = None
                    logger.debug('pk.parent', pk.parent)
                self.secretpgpykeys.append(sk)
        self.secretpgpykeys = sorted(self.secretpgpykeys,
                                     key=attrgetter('fingerprint',
                                                    'is_primary'),
                                     reverse=True)
        logger.debug('secret keys %s', self.secretpgpykeys)

    def add_key(self, pgpykey=None):
        if pgpykey is None:
            pgpykey = self.own_pgpykey
        if not pgpykey.is_public:
            self.secretpgpykeys.append(pgpykey)
            self.publicpgpykeys.append(pgpykey.pubkey)
        else:
            self.publicpgpykeys.append(pgpykey)
        logger.debug('publicppgpykeys %s',  self.publicpgpykeys)
        logger.debug('secretppgpykeys %s',  self.secretpgpykeys)

    def gen_secret_key(self,
                       emailadr='alice@testsuite.autocrypt.org',
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
        self.own_pgpykey = PGPKey.new(alg_key, size)
        # NOTE: pgpy implements separate attributes for name and e-mail
        # address. Name is mandatory.
        # Here e-mail address is used for the attribute name .
        # If name attribute would be set to empty string
        # and email to the e-mail address, the uid would be
        # ' <e-mail address>', for instance:
        # " <alice@testsuite.autocrypt.org>" - which we do not want.
        uid = PGPUID.new(emailadr)
        logger.debug('uid %s', uid)
        # NOTE: it is needed to specify all arguments in current pgpy
        # version.
        # FIXME: see which defaults we would like here
        self.own_pgpykey.add_uid(
                uid,
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
            self.own_pgpykey.add_subkey(
                                subkey,
                                usage={KeyFlags.EncryptCommunications,
                                       KeyFlags.EncryptStorage})
            logger.debug('Created subkey')
            logger.debug('type(ubkey.parent) %s', type(subkey.parent))
        if protected is True:
            passphrase = getpass.getpass()
            self.own_pgpykey.protect(
                             passphrase,
                             SymmetricKeyAlgorithm.AES256,
                             HashAlgorithm.SHA256)
            logger.debug('Key protected')
        self.own_pgpykey.certify(self.own_pgpykey.userids[0])
        logger.debug('self-signed key')
        self.own_keyhandle = self.own_pgpykey.fingerprint.keyid
        # put the key as exported ASCII-armored in ring
        self.export_key(self.own_pgpykey)
        self.publicpgpykeys.append(self.own_pgpykey.pubkey)
        self.secretpgpykeys.append(self.own_pgpykey)
        self.load_pgpykr()
        # self.add_key(self.own_pgpykey)
        # self.load_keys_from_pgpykr()

        logger.debug('Created key pair %s', self.own_keyhandle)
        return self.own_keyhandle

    def export_skey(self, pgpykey=None):
        if pgpykey is None:
            pgpykey = self.own_pgpykey
        assert not pgpykey.is_public
        secretkeydata = self.get_secret_keydata(armor=True,
                                                pgpykey=pgpykey)
        with open(os.path.join(self.pgpydir, pgpykey.fingerprint.keyid
                               + '.key'), 'w') as fd:
            fd.write(secretkeydata)

    def export_pkey(self, pgpykey=None):
        if pgpykey is None:
            pgpykey = self.own_pgpykey.pubkey
        if not pgpykey.is_public:
            pgpykey = pgpykey.pubkey
        publickeydata = self.get_public_keydata(armor=True,
                                                pgpykey=pgpykey)
        with open(os.path.join(self.pgpydir, pgpykey.fingerprint.keyid
                               + '.asc'), 'w') as fd:
            fd.write(publickeydata)

    def export_key(self, pgpykey=None):
        if pgpykey is None:
            pgpykey = self.own_pgpykey
        if pgpykey.is_public:
            self.export_pkey(pgpykey)
        else:
            self.export_skey(pgpykey)
            self.export_pkey(pgpykey.pubkey)

    def get_key_from_keyhandle(self, keyhandle):
        logger.debug('keyhandle %s',  keyhandle)
        keys = [k for k in self.secretpgpykeys
                if (k.fingerprint.keyid == keyhandle
                    or k.fingerprint.shortid == keyhandle)]
        logger.debug('keys %s', keys)
        if len(keys) > 0:
            logger.debug('found secret key with keyhandle')
            return keys[0]
        keys = [k for k in self.publicpgpykeys
                if (k.fingerprint.keyid == keyhandle
                    or k.fingerprint.shortid == keyhandle)]
        if len(keys) > 0:
            logger.debug('found public key with keyhandle')
            return keys[0]
        logger.debug('not found key with keyhandle')
        return None

    def get_userid_from_keyhandle(self, keyhandle=None):
        if keyhandle is None:
            return self.own_pgpykey.userids[0].name
        uids = [k.userids[0] for k in self.publicpgpykeys
                if (len(k.userids) > 0
                    and k.fingerprint.keyid == keyhandle)]
        if len(uids) > 0:
            return uids[0]
        return None

    def get_public_keydata(self, keyhandle=None, armor=False,
                           b64=False, pgpykey=None):
        if pgpykey is None and keyhandle is None:
            pgpykey = self.own_pgpykey.pubkey
        elif pgpykey is None and keyhandle is not None:
            pgpykey = self.get_key_from_keyhandle(keyhandle)
        elif pgpykey is not None and not pgpykey.is_public:
            pgpykey = pgpykey.pubkey
        elif pgpykey is not None:
            pgpykey = pgpykey
        if armor is True:
            keydata = str(pgpykey)
        else:
            keydata = key_bytes(pgpykey)
        if b64 is True:
            keydata = key_base64(pgpykey)
        return keydata

    def get_secret_keydata(self, keyhandle=None, armor=False, pgpykey=None):
        if pgpykey is None and keyhandle is None:
            pgpykey = self.own_pgpykey
        elif pgpykey is None and keyhandle is not None:
            pgpykey = self.get_key_from_keyhandle(keyhandle)
        elif pgpykey is not None:
            pgpykey = pgpykey
        else:
            pgpykey = pgpykey
        assert not pgpykey.is_public
        if armor is True:
            keydata = str(pgpykey)
        else:
            keydata = key_bytes(pgpykey)
        return keydata

    # def keyuids(self):
    #     return [uid.name for uid in self.own_pgpykey.userids]

    # def keyinfo(self):
    #     ki = (
    #         self.own_pgpykey.key_algorithm.value,
    #         self.own_pgpkey.userids[0].name,
    #         self.own_pgpykey.key_size,
    #         self.own.pgpykey.fingerprint.keyid,
    #         self.own_pgpykey.subkeys.items(),
    #         [uid.name for uid in self.own_pgpykey.userids],
    #         self.own_pgpykey.created
    #     )
    #     return ki

    def list_secret_keyinfos(self, keyhandle=None):
        return self._parse_list(type_public=False)

    def list_public_keyinfos(self, keyhandle=None):
        return self._parse_list()

    def _parse_list(self, type_public=True):
        # NOTE: the subkeys have to be at the end of the list to pass
        # the tests
        keyinfos = []
        if type_public is True:
            keys = self.publicpgpykeys
        else:
            keys = self.secretpgpykeys
        for k in keys:
            # FIXME: use only primaries?
            if len(k.userids) > 0:
                uid = k.userids[0].name
            else:
                uid = k.parent.userids[0].name
            keyinfos.append(KeyInfo(type=k.key_algorithm.value,
                                    bits=k.key_size,
                                    uid=uid,
                                    id=k.fingerprint.keyid,
                                    date_created=k.created))
        logger.debug('keyinfos %s', keyinfos)
        return keyinfos

    def _find_keyhandle(self, string,
                        _pattern=re.compile("key (?:ID )?([0-9A-F]+)")):
        # search for string like "key <longid/shortid>"
        m = _pattern.search(string)
        assert m and len(m.groups()) == 1, string
        x = m.groups()[0]
        # now search the fingerprint if we only have a shortid
        if len(x) <= 8:
            keyinfos = self.list_public_keyinfos(x)
            for k in keyinfos:
                if k.match(x):
                    return k.id
            raise ValueError("could not find fingerprint %r in %r" %
                             (x, keyinfos))
        # note that this might be a 16-char fingerprint or a 40-char one
        # (gpg-2.1.18)
        return x

    def encrypt(self, data, recipients):
        # The symmetric cipher should be specified, in case the first
        # preferred cipher is not the same for all recipients' public keys
        # cipher = SymmetricKeyAlgorithm.AES256
        # sessionkey = cipher.gen_key()
        enc_msg = PGPMessage.new(data)
        enc_msg | self.own_pgpykey.sign(enc_msg)
        logger.debug('recipients %s',  recipients)
        for r in recipients:
            # FIXME: this fail because PGPy try to find self_signatures
            # in subkey
            k = self.get_key_from_keyhandle(r)
            logger.debug('type(k.pubkey) %s', type(k.pubkey))
            logger.debug('k.pubkey.subkeys %s', k.pubkey.subkeys)
            enc_msg = k.pubkey.encrypt(enc_msg)
            logger.debug('enc_msg %s',  enc_msg)

        # do at least this as soon as possible after encrypting to the
        # final recipient
        # del sessionkey
        return enc_msg

    def sign(self, data, keyhandle=None):
        if (keyhandle is not None and
                self.get_key_from_keyhandle(keyhandle) is not None):
            pgpykey = self.get_key_from_keyhandle(keyhandle)
        else:
            pgpykey = self.own_pgpykey
        sig_data = pgpykey.sign(data)
        return str(sig_data)

    def verify(self, data, signature):
        # TODO:
        # signature = SignatureVerification()
        ver = self.own_pgpykey.verify(data, signature)
        return ver

    def decrypt(self, enc_data):
        enc_data_pgpy = PGPMessage.from_blob(enc_data)
        out = self.own_pgpykey.decrypt(enc_data_pgpy)
        # TODO: extract keyinfos, for instance
        # keyinfos = [('RSA', '2048', 'longid', 'uid', 'created')]
        return out,  []

    def import_keydata(self, keydata):
        pgpykey, _ = PGPKey.from_blob(keydata)
        # TODO: add in self.public/secretpgpykeys
        return pgpykey.fingerprint.keyid


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
        return "KeyInfo(id={id!r}, uids={uids!r}, bits={bits}, \
                type={type})".format(
            **self.__dict__)

    __repr__ = __str__
