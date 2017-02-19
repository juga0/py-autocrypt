# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

""" mime message parsing and manipulation for Autocrypt usage. """

from __future__ import unicode_literals, print_function
import sys
import email.parser
import base64

def make_ac_header_value(emailadr, keydata, prefer_encrypt="notset", keytype="p"):
    assert keydata
    key = base64.b64encode(keydata) if isinstance(keydata, bytes) else keydata
    if isinstance(key, bytes):
        key = key.decode("ascii")
    l = ["to=" + emailadr, "key=" + key]
    if prefer_encrypt != "notset":
        l.insert(1, "prefer-encrypt=" + prefer_encrypt)
    if keytype != "p":
        l.insert(1, "type=" + keytype)
    return "; ".join(l)


def parse_email_addr(string):
    """ return a (prefix, emailadr) tuple. """
    return email.utils.parseaddr(string)

def parse_message_from_file(fp):
    return email.parser.Parser().parse(fp)

def parse_message_from_string(string):
    return email.parser.Parser().parsestr(string)


def parse_one_ac_header_from_string(string):
    msg = email.parser.Parser().parsestr(string)
    return parse_one_ac_header_from_msg(msg)


def parse_all_ac_headers_from_msg(msg):
    autocrypt_headers = msg.get_all("Autocrypt") or []
    return [parse_ac_headervalue(inb)
                for inb in autocrypt_headers if inb]

def parse_one_ac_header_from_msg(msg):
    all_results = parse_all_ac_headers_from_msg(msg)
    if len(all_results) == 1:
        return all_results[0]
    if len(all_results) > 1:
        raise ValueError("more than one Autocrypt header\n%s" %
                         "\n".join(msg.get_all("Autocrypt")))
    return {}


def parse_ac_headervalue(value):
    """ return a autocrypt attribute dictionary parsed
    from the specified autocrypt header value.  Unspecified
    default values for prefer-encrypt and the key type are filled in."""
    parts = value.split(";")
    result_dict = {"prefer-encrypt": "notset", "type": "p"}
    for x in parts:
        kv = x.split("=", 1)
        name, value = [x.strip() for x in kv]
        if name == "key":
            value = "".join(value.split())
        result_dict[name] = value
    return result_dict


def verify_ac_dict(ac_dict):
    """ return a list of errors from checking the autocrypt attribute dict.
    if the returned list is empty no errors were found.
    """
    l = []
    for name in ac_dict:
        if name not in ("key", "to", "type", "prefer-encrypt") and name[0] != "_":
            l.append("unknown critical attr '%s'" %(name, ))
    #keydata_base64 = "".join(ac_dict["key"])
    #base64.b64decode(keydata_base64)
    if "type" not in ac_dict:
        l.append("type missing")
    if "key" not in ac_dict:
        l.append("key missing")
    if ac_dict["type"] != "p":
        l.append("unknown key type '%s'" % (ac_dict["type"], ))
    if ac_dict["prefer-encrypt"] not in ("notset", "yes", "no"):
        l.append("unknown prefer-encrypt setting '%s'" %
                 (ac_dict["prefer-encrypt"]))
    return l


# adapted from ModernPGP:memoryhole/generators/generator.py which
# was adapted from notmuch:devel/printmimestructure
def render_mime_structure(z, prefix='└', stream=sys.stdout):
    '''z should be an email.message.Message object'''
    fname = '' if z.get_filename() is None else ' [' + z.get_filename() + ']'
    cset = '' if z.get_charset() is None else ' (' + z.get_charset() + ')'
    disp = z.get_params(None, header='Content-Disposition')
    if (disp is None):
        disposition = ''
    else:
        disposition = ''
        for d in disp:
            if d[0] in [ 'attachment', 'inline' ]:
                disposition = ' ' + d[0]

    if 'subject' in z:
        subject = ' (Subject: %s)' % z['subject']
    else:
        subject = ''
    if (z.is_multipart()):
        print(prefix + '┬╴' + z.get_content_type() + cset +
                disposition + fname, z.as_string().__len__().__str__()
                + ' bytes' + subject, file=stream)
        if prefix.endswith('└'):
            prefix = prefix.rpartition('└')[0] + ' '
        if prefix.endswith('├'):
            prefix = prefix.rpartition('├')[0] + '│'
        parts = z.get_payload()
        i = 0
        while (i < parts.__len__()-1):
            render_mime_structure(parts[i], prefix + '├', stream=stream)
            i += 1
        render_mime_structure(parts[i], prefix + '└', stream=stream)
        # FIXME: show epilogue?
    else:
        print(prefix + '─╴'+ z.get_content_type() + cset + disposition
                + fname, z.get_payload().__len__().__str__(),
                'bytes' + subject, file=stream)