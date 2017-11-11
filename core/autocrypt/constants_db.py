#
"""."""

import logging
import os.path


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(BASE_DIR)

SQLITE_PATH = os.path.join(BASE_DIR, 'db.sqlite3')

SQLITE_CREATE_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS account (
    addr varchar(250) PRIMARY KEY ASC,
    kd text,
    pe varchar(250))""",
    """CREATE TABLE IF NOT EXISTS peer (
    addr varchar(250) PRIMARY KEY ASC,
    ls text,
    lsa text,
    pe varchar(250))""",
    """CREATE TABLE IF NOT EXISTS peers (id INTEGER PRIMARY KEY ASC,
    addr varchar(250))""",
    """CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY ASC,
    addr varchar(250))"""
    ]

SQLITE_CREATE_STATEMENT = """
BEGIN;
--
-- Create model Account
--
CREATE TABLE IF NOT EXISTS "ac_account" (
"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
"enabled" bool NOT NULL,
"pe" varchar(20) NOT NULL,
"skey" BLOB NOT NULL,
"pkey" BLOB NOT NULL);
--
-- Create model AccountList
--
CREATE TABLE IF NOT EXISTS "ac_accountlist" (
"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
"addr" varchar(254) NOT NULL,
"account_id" integer NOT NULL REFERENCES "ac_account" ("id"));
--
-- Create model Peer
--
CREATE TABLE IF NOT EXISTS "ac_peer" (
"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
"pe" varchar(20) NOT NULL,
"pkey" BLOB NOT NULL,
"ls" datetime NOT NULL,
"ats" datetime NOT NULL,
"gpk" BLOB NULL,
"gts" datetime NULL);
--
-- Create model PeerList
--
CREATE TABLE IF NOT EXISTS "ac_peerlist" (
"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
"addr" varchar(254) NOT NULL,
"peer_id" integer NOT NULL REFERENCES
"ac_peer" ("id"));
--
-- Create model Profile
--
CREATE TABLE IF NOT EXISTS "ac_profile" (
"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
"accounts_id" integer NOT NULL REFERENCES "ac_accountlist" ("id"),
"peers_id" integer NOT NULL REFERENCES "ac_peerlist" ("id"));

CREATE INDEX IF NOT EXISTS "ac_accountlist_account_id_8489b227" ON "ac_accountlist" ("account_id");
CREATE INDEX IF NOT EXISTS "ac_peerlist_peer_id_31372d94" ON "ac_peerlist" ("peer_id");
CREATE INDEX IF NOT EXISTS "ac_profile_accounts_id_66f5278a" ON "ac_profile" ("accounts_id");
CREATE INDEX IF NOT EXISTS "ac_profile_peers_id_1e87de75" ON "ac_profile" ("peers_id");
COMMIT;
"""

INSERT_STATEMENT = """INSERT INTO {} ({}), ({})"""
INSERT_ACCOUNT = """INSERT INTO account (addr, pe, kd), ({})"""
