# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

""" BinGPG is a "gpg" or "gpg2" command line wrapper which
implements all operations we need for Autocrypt usage.
It is not meant as a general wrapper outside Autocrypt
contexts.
"""

from __future__ import print_function, unicode_literals
import logging
from distutils.version import LooseVersion as V
import os
import sys
from subprocess import Popen, PIPE
from contextlib import contextmanager
from base64 import b64encode
import tempfile
import re
iswin32 = sys.platform == "win32" or (getattr(os, '_name', False) == 'nt')


def b64encode_u(x):
    res = b64encode(x)
    if isinstance(res, bytes):
        res = res.decode("ascii")
    return res


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


class InvocationFailure(Exception):
    def __init__(self, ret, cmd, out, err, extrainfo=None):
        self.ret = ret
        self.cmd = cmd
        self.out = out
        self.err = err
        self.extrainfo = extrainfo

    def __str__(self):
        lines = ["GPG Command '%s' retcode=%d" % (self.cmd, self.ret)]
        for name, olines in [("stdout:", self.out), ("stderr:", self.err)]:
            lines.append(name)
            for line in olines.splitlines():
                lines.append("  " + line)
        if self.extrainfo:
            lines.append(self.extrainfo)
        return "\n".join(lines)


class BinGPG(object):
    """ basic wrapper for gpg command line invocations. """
    InvocationFailure = InvocationFailure

    def __init__(self, homedir=None, gpgpath="gpg"):
        self.homedir = homedir
        p = find_executable(gpgpath)
        if p is None:
            raise ValueError("could not find binary for {!r}".format(gpgpath))
        self.gpgpath = p
        self._ensure_init()

    def __str__(self):
        return "BinGPG(gpgpath={gpgpath!r}, homedir={homedir!r})".format(
            gpgpath=self.gpgpath, homedir=self.homedir)

    @cached_property
    def isgpg2(self, min_version=V("2.0")):
        return V(self.get_version()) >= min_version

    def _ensure_init(self):
        if self.homedir is None:
            return

        if not os.path.exists(self.homedir):
            # we create the dir if the basedir exists, otherwise we fail
            os.mkdir(self.homedir)
            os.chmod(self.homedir, 0o700)

        # fix bad defaults for certain gpg2 versions
        if V("2.0") <= V(self.get_version()) < V("2.1.12"):
            p = os.path.join(self.homedir, "gpg-agent.conf")
            if not os.path.exists(p):
                with open(p, "w") as f:
                    f.write("allow-loopback-pinentry\n")

    def killagent(self):
        if self.isgpg2:
            args = [find_executable("gpg-connect-agent"), "--no-autostart"]
            args += self._homedirflags + ["KILLAGENT"]
            popen = Popen(args)
            popen.wait()

    @contextmanager
    def temp_written_file(self, data):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
        try:
            yield f.name
        finally:
            os.remove(f.name)

    @property
    def _homedirflags(self):
        return ["--homedir", self.homedir] if self.homedir else []

    @cached_property
    def _nopassphrase(self):
        return ((["--pinentry-mode=loopback"] if self.isgpg2 else []) +
                ["--passphrase", "''"])

    def _gpg_out(self, argv, input=None, strict=False, encoding="utf8"):
        return self._gpg_outerr(argv, input=input, strict=strict, encoding=encoding)[0]

    def _gpg_outerr(self, argv, input=None, strict=False, encoding="utf8"):
        """ return stdout and stderr output of invoking gpg with the
        specified parameters.

        If the invocation leads to a non-zero exit
        status an InvocationFailure exception is thrown.  It is also
        thrown if strict is True and there was non-empty stderr output.
        stderr output will always be returned as a text type (utf8-decoded)
        while stdout output is returned decoded if encoding is set (default is "utf8").
        If you want binary stdout output specify encoding=None.
        """
        args = [self.gpgpath, "--batch"] + self._homedirflags
        # make sure we use unicode for all provided arguments

        def ensure_unicode(x):
            return x.decode("utf8") if isinstance(x, bytes) else x
        args.extend(map(ensure_unicode, argv))

        # open the process with a C locale, pipe everything
        env = os.environ.copy()
        env["LANG"] = "C"
        popen = Popen(args, stdout=PIPE, stderr=PIPE, stdin=PIPE, env=env)

        # some debugging info
        G = os.environ.get("GNUPGHOME")
        extra = "" if not G else ("GNUPGHOME=" + G + " ")
        logging.debug("$ %s%s", extra, " ".join(args))

        out, err = popen.communicate(input=input)
        ret = popen.wait()
        if ret == 130:
            raise KeyboardInterrupt("detected in gpg invocation")
        err = err.decode("utf8")
        if encoding:
            out = out.decode(encoding)
        if ret != 0 or (strict and err):
            raise self.InvocationFailure(ret, " ".join(args),
                                         out=out, err=err)
        return out, err

    @cached_property
    def _version_info(self):
        return self._gpg_out(['--version'])

    def get_version(self):
        vline = self._version_info.split('\n', 1)[0]
        return vline.split(' ')[2]

    def supports_eddsa(self):
        for l in self._version_info.split('\n'):
            if l.startswith('Pubkey:'):
                return 'eddsa' in map(
                    lambda x: x.strip().lower(), l.split(':', 1)[1].split(','))
        return False

    def gen_secret_key(self, emailadr):
        spec = "\n".join([
            "Key-Type: RSA",
            "Key-Length: 2048",
            "Key-Usage: sign",
            "Subkey-Type: RSA",
            "Subkey-Length: 2048",
            "Subkey-Usage: encrypt",
            # "Name-Real: " + uid,
            "Name-Email: " + emailadr,
            "Expire-Date: 0",
            "%commit"
        ]).encode("utf8")
        with self.temp_written_file(spec) as fn:
            try:
                out, err = self._gpg_outerr(self._nopassphrase + ["--gen-key", fn])
            except InvocationFailure as e:
                e.extrainfo = open(fn).read()
                raise

        keyhandle = self._find_keyhandle(err)
        logging.debug("created secret key: %s", keyhandle)
        return keyhandle

    def list_secret_keyinfos(self, keyhandle=None):
        args = ["--skip-verify", "--with-colons", "--list-secret-keys"]
        if keyhandle is not None:
            args.append(keyhandle)
        return self._parse_list(args, ("sec", "ssb"))

    def list_public_keyinfos(self, keyhandle=None):
        args = ["--skip-verify", "--with-colons", "--list-public-keys"]
        if keyhandle is not None:
            args.append(keyhandle)
        return self._parse_list(args, ("pub", "sub"))

    def _parse_list(self, args, types):
        out = self._gpg_out(args)
        keyinfos = []
        last_main_type_keyinfo = None
        for line in out.splitlines():
            parts = line.split(":")
            if parts[0] in types:
                keyinfos.append(
                    KeyInfo(type=parts[3], bits=int(parts[2]), uid=parts[9],
                            id=parts[4], date_created=parts[5]))
                if parts[0] == types[0]:
                    last_main_type_keyinfo = keyinfos[-1]
            elif parts[0] == "uid":
                last_main_type_keyinfo.uids.append(parts[9])
        return keyinfos

    def _find_keyhandle(self, string, _pattern=re.compile("key (?:ID )?([0-9A-F]+)")):
        m = _pattern.search(string)
        assert m and len(m.groups()) == 1, string
        x = m.groups()[0]

        # now search the fingerprint if we only have a shortid
        if len(x) <= 8:   # keyid has 8 hex bytes
            keyinfos = self.list_public_keyinfos(x)
            for k in keyinfos:
                if k.match(x):
                    return k.id
            raise ValueError("could not find fingerprint %r in %r" % (x, keyinfos))
        # note that this might be a 16-char fingerprint or a 40-char one (gpg-2.1.18)
        return x

    def list_secret_key_packets(self, keyhandle):
        return self.list_packets(self.get_secret_keydata(keyhandle))

    def list_public_key_packets(self, keyhandle):
        return self.list_packets(self.get_public_keydata(keyhandle))

    def list_packets(self, keydata):
        out = self._gpg_out(["--list-packets"], input=keydata)
        # build up a list of (pkgname, pkgvalue, lines) tuples
        packets = []
        lines = []
        last_package_type = None
        for rawline in out.splitlines():
            line = rawline.strip()
            c = line[0:1]
            if c == "#":
                continue
            if c == ":":
                i = line[1:].find(c)
                if i != -1:
                    ptype = line[1: i + 1]
                    pvalue = line[i + 2:].strip()
                    if last_package_type is not None:
                        packets.append(last_package_type + (lines,))
                        lines = []
                    last_package_type = (ptype, pvalue)
            else:
                assert last_package_type, line
                lines.append(line)
        else:
            packets.append(last_package_type + (lines,))
        return packets

    def get_public_keydata(self, keyhandle, armor=False, b64=False):
        args = ["-a"] if armor else []
        args.extend(["--export-options=export-minimal", "--export", str(keyhandle)])
        out = self._gpg_out(args, strict=True, encoding=None)
        return out if not b64 else b64encode_u(out)

    def get_secret_keydata(self, keyhandle, armor=False):
        args = ["-a"] if armor else []
        args.extend(self._nopassphrase + ["--export-options=export-minimal",
                    "--export-secret-key", keyhandle])
        return self._gpg_out(args, strict=True, encoding=None)

    def encrypt(self, data, recipients):
        recs = []
        for r in recipients:
            recs.extend(["--recipient", r])
        return self._gpg_out(recs + ["--encrypt", "--always-trust"], input=data,
                             encoding=None)

    def sign(self, data, keyhandle):
        args = self._nopassphrase + ["--detach-sign", "-u", keyhandle]
        return self._gpg_out(args, input=data, encoding=None)

    def verify(self, data, signature):
        with self.temp_written_file(signature) as sig_fn:
            out, err = self._gpg_outerr(["--verify", sig_fn, "-"], input=data)
        return self._find_keyhandle(err)

    def decrypt(self, enc_data):
        args = self._nopassphrase + ["--with-colons", "--decrypt"]
        out, err = self._gpg_outerr(args, input=enc_data, encoding=None)
        lines = err.splitlines()
        keyinfos = []
        while lines:
            line1 = lines.pop(0)
            m = re.match("gpg.*with (\d+)-bit (\w+).*"
                         "ID (\w+).*created (.*)", line1)
            if m:
                bits, keytype, id, date = m.groups()
                line2 = lines.pop(0)
                if line2.startswith("    "):
                    uid = line2.strip().strip('"')
                keyinfos.append(KeyInfo(keytype, bits, id, uid, date))
        return out, keyinfos

    def import_keydata(self, keydata):
        out, err = self._gpg_outerr(["--skip-verify", "--import"], input=keydata)
        return self._find_keyhandle(err)


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


def find_executable(name):
    """ return a path object found by looking at the systems
        underlying PATH specification.  If an executable
        cannot be found, None is returned. copied and adapted
        from py.path.local.sysfind.
    """
    if os.path.isabs(name):
        return name if os.path.isfile(name) else None
    else:
        if iswin32:
            paths = os.environ['Path'].split(';')
            if '' not in paths and '.' not in paths:
                paths.append('.')
            try:
                systemroot = os.environ['SYSTEMROOT']
            except KeyError:
                pass
            else:
                paths = [re.sub('%SystemRoot%', systemroot, path)
                         for path in paths]
        else:
            paths = os.environ['PATH'].split(':')
        tryadd = []
        if iswin32:
            tryadd += os.environ['PATHEXT'].split(os.pathsep)
        tryadd.append("")

        for x in paths:
            for addext in tryadd:
                p = os.path.join(x, name) + addext
                try:
                    if os.path.isfile(p):
                        return p
                except Exception:
                    pass
    return None
