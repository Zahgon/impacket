# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Functions for Microsoft Windows 2000 Kerberos Change Password
#   and Set Password Protocols
#
# References:
#   https://www.rfc-editor.org/rfc/rfc3244.txt
#
# Author:
#   Thomas Fargeix (@Alef-Burzmali)
#

import base64
import binascii
import datetime
import os
import struct

from pyasn1.type import namedtype, univ
from pyasn1.codec.der import decoder, encoder

from impacket import LOG
from impacket.dcerpc.v5.enum import Enum

from .kerberosv5 import getKerberosTGT, sendReceive
from .asn1 import (_sequence_component, _sequence_optional_component, seq_set,
                   Realm, PrincipalName, Authenticator,
                   AS_REP, AP_REQ, AP_REP,
                   KRB_PRIV, EncKrbPrivPart)
from .ccache import CCache
from .constants import PrincipalNameType, ApplicationTagNumbers, AddressType, encodeFlags
from .crypto import Key, get_random_bytes
from .types import Principal, KerberosTime, Ticket


# KPASSWD constants and structures

KRB5_KPASSWD_PORT = 464
KRB5_KPASSWD_PROTOCOL_VERSION = 0xFF80
KRB5_KPASSWD_TGT_SPN = "kadmin/changepw"


class KPasswdResultCodes(Enum):
    SUCCESS = 0
    MALFORMED = 1
    HARDERROR = 2
    AUTHERROR = 3
    SOFTERROR = 4
    ACCESSDENIED = 5
    BAD_VERSION = 6
    INITIAL_FLAG_NEEDED = 7
    UNKNOWN = 0xFFFF


RESULT_MESSAGES = {
    0: "password changed successfully",
    1: "protocol error: malformed request",
    2: "server error (KRB5_KPASSWD_HARDERROR)",
    3: "authentication failed (may also indicate that the target user was not found)",
    4: "password change rejected (KRB5_KPASSWD_SOFTERROR)",
    5: "access denied",
    6: "protocol error: bad version",
    7: "protocol error: initial flag needed",
    0xFFFF: "unknown error",
}


class ChangePasswdData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("newpasswd", 0, univ.OctetString()),  # cleartext password
        _sequence_optional_component("targname", 1, PrincipalName()),
        _sequence_optional_component("targrealm", 2, Realm()),
    )


# PasswordPolicy parsing
# From https://github.com/GhostPack/Rubeus/blob/84610f13e4d47d1a952be3f5348dd1cb18bd92fa/Rubeus/lib/Reset.cs#L180


class PasswordPolicyFlags(Enum):
    Complex = 0x1
    NoAnonChange = 0x2
    NoClearChange = 0x4
    LockoutAdmins = 0x8
    StoreCleartext = 0x10
    RefusePasswordChange = 0x20


def _decodePasswordPolicy(ppolicyString):
    pass


# KPASSWD protocol messages


class KPasswdError(Exception):
    pass


def createKPasswdRequest(principal, domain, newPasswd, tgs, cipher, sessionKey, subKey,
                         targetPrincipal=None, targetDomain=None, sequenceNumber=None,
                         now=None, hostname=b"localhost"):

    # Generate the parameters that we need
    pass


def decodeKPasswdReply(encoded, cipher, subKey):
    # Extract the AP_REP and KRB_PRIV
    pass


# Wrapper functions

def changePassword(clientName, domain, newPasswd,
                   oldPasswd="", oldLmhash="", oldNthash="", aesKey="", TGT=None,
                   kdcHost=None, kpasswdHost=None, kpasswdPort=KRB5_KPASSWD_PORT, subKey=None):
    """
    Change the password of the requesting user with RFC 3244 Kerberos Change-Password protocol.

    At least one of oldPasswd, (oldLmhash, oldNthash) or (TGT, aesKey) should be defined.

    :param string clientName:   username of the account changing their password
    :param string domain:       domain of the account changing their password
    :param string newPasswd:    new password for the account
    :param string oldPasswd:    current password of the account
    :param string oldLmhash:    current LM hash of the account
    :param string oldNthash:    current NT hash of the account
    :param string aesKey:       current AES key of the account
    :param string TGT:          TGT of the account. It must be a TGT with a SPN of kadmin/changepw
    :param string kdcHost:      KDC address/hostname, used for Kerberos authentication
    :param string kpasswdHost:  KDC exposing the kpasswd service (TCP/464, UDP/464),
                                used when sending the password change requests
                                (Default: same as kdcHost)
    :param int kpasswdPort:     TCP port where kpasswd is exposed (Default: 464)
    :param string subKey:       Subkey to use to encrypt the password change request
                                (Default: generate a random one)

    :return void:               Raise an KPasswdError exception on error.
    """
    pass


def setPassword(clientName, domain, targetName, targetDomain, newPasswd,
                oldPasswd="", oldLmhash="", oldNthash="", aesKey="", TGT=None,
                kdcHost=None, kpasswdHost=None, kpasswdPort=KRB5_KPASSWD_PORT, subKey=None):
    """
    Set the password of a target account with RFC 3244 Kerberos Set-Password protocol.
    Requires "Reset password" permission on the target, for the user.

    At least one of oldPasswd, (oldLmhash, oldNthash) or (TGT, aesKey) should be defined.

    :param string clientName:   username of the account performing the reset
    :param string domain:       domain of the account performing the reset
    :param string targetName:   username of the account whose password will be changed
    :param string targetDomain: domain of the account whose password will be changed
    :param string newPasswd:    new password for the target account
    :param string oldPasswd:    current password of the account performing the reset
    :param string oldLmhash:    current LM hash of the account performing the reset
    :param string oldNthash:    current NT hash of the account performing the reset
    :param string aesKey:       current AES key of the account performing the reset
    :param string TGT:          TGT of the account performing the reset
                                It must be a TGT with a SPN of kadmin/changepw
    :param string kdcHost:      KDC address/hostname, used for Kerberos authentication
    :param string kpasswdHost:  KDC exposing the kpasswd service (TCP/464, UDP/464),
                                used when sending the password change requests
                                (Default: same as kdcHost)
    :param int kpasswdPort:     TCP port where kpasswd is exposed (Default: 464)
    :param string subKey:       Subkey to use to encrypt the password change request
                                (Default: generate a random one)

    :return bool:               True if successful, raise an KPasswdError exception on error.
    """
    pass
