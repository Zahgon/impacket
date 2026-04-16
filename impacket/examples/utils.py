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
#   Utility and helper functions for the example scripts
#
# Author:
#   Martin Gallo (@martingalloar)
#
import re


# Regular expression to parse target information
target_regex = re.compile(r"(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)")


# Regular expression to parse credentials information
credential_regex = re.compile(r"(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?")


def parse_target(target):
    """ Helper function to parse target information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>@HOSTNAME

    :param target: target to parse
    :type target: string

    :return: tuple of domain, username, password and remote name or IP address
    :rtype: (string, string, string, string)
    """
    domain, username, password, remote_name = target_regex.match(target).groups('')

    # In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    return domain, username, password, remote_name


def parse_credentials(credentials):
    """ Helper function to parse credentials information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>

    :param credentials: credentials to parse
    :type credentials: string

    :return: tuple of domain, username and password
    :rtype: (string, string, string)
    """
    domain, username, password = credential_regex.match(credentials).groups('')

    return domain, username, password

# ----------

from impacket.smbconnection import SMBConnection, SessionError
import ldap3
import ssl
from binascii import unhexlify
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

def _get_machine_name(machine, fqdn=False):
    pass

def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    pass

def _init_ldap_connection(target, use_ssl, domain, username, password, lmhash, nthash, k, dc_ip, aesKey):
    pass

def init_ldap_session(domain, username, password, lmhash, nthash, k, dc_ip, dc_host, aesKey, use_ldaps):
    pass

# ----------

from impacket.ldap import ldap
import logging
def ldap_login(target, base_dn, kdc_ip, kdc_host, do_kerberos, username, password, domain, lmhash, nthash, aeskey, ldaps_flag=False, target_domain=None, fqdn=False):
    pass

# ----------

EMPTY_LM_HASH = 'AAD3B435B51404EEAAD3B435B51404EE'
def parse_identity(credentials, hashes=None, no_pass=False, aesKey=None, k=False, getpass_msg='Password:'):
    pass

# ----------

def get_address(ip, port, ipv6=False):
    address = (ip, port)
    address_family = socket.AF_INET
    if ipv6:
        address_family = socket.AF_INET6
        # scope_id (after %) can be present or not - if not, default: 0
        ip_parts = ip.split('%')
        scope_id = ip_parts[1] if len(ip_parts) == 2 else 0
        # convert scope_id to int (expected by s.connect)
        # if exception, assume the interface name and convert to index
        try:
            scope_id = int(scope_id)
        except ValueError:
            scope_id = socket.if_nametoindex(scope_id)
        address = address + (0, scope_id)
    return address_family, address

import socket
def get_connected_socket(ip, port, ipv6=False):
    pass
