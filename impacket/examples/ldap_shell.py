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
#   Mini shell using some of the LDAP functionalities of the library
#
# Author:
#   Mathieu Gascon-Lefebvre (@mlefebvre)
#
import re
import string
import sys
import cmd
import random
import ldap3
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM
from ldap3.utils.conv import escape_filter_chars
from six import PY2
import shlex
from impacket import LOG
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACCESS_ALLOWED_ACE, ACE, OBJECTTYPE_GUID_MAP
from impacket.ldap import ldaptypes
from impacket.examples.ntlmrelayx.utils import shadow_credentials
import uuid


class LdapShell(cmd.Cmd):
    LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

    def __init__(self, tcp_shell, domain_dumper, client):
        cmd.Cmd.__init__(self, stdin=tcp_shell.stdin, stdout=tcp_shell.stdout)

        if PY2:
            # switch to unicode.
            reload(sys) # noqa: F821 pylint:disable=undefined-variable
            sys.setdefaultencoding('utf8')

        sys.stdout = tcp_shell.stdout
        sys.stdin = tcp_shell.stdin
        sys.stderr = tcp_shell.stdout
        self.use_rawinput = False
        self.shell = tcp_shell

        self.prompt = '\n# '
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.client = client
        self.domain_dumper = domain_dumper

    def emptyline(self):
        pass

    def onecmd(self, s):
        pass

    def create_empty_sd(self):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = 32772
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        # BUILTIN\Administrators
        sd['OwnerSid'].fromCanonical('S-1-5-32-544')
        sd['GroupSid'] = b''
        sd['Sacl'] = b''
        acl = ldaptypes.ACL()
        acl['AclRevision'] = 4
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0
        acl.aces = []
        sd['Dacl'] = acl
        return sd

    def create_allow_ace(self, sid):
        nace = ldaptypes.ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = 983551 # Full control
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        nace['Ace'] = acedata
        return nace

    def do_write_gpo_dacl(self, line):
        pass

    def do_add_computer(self, line):
        pass

    def do_rename_computer(self, line):
        pass

    def do_add_user(self, line):
        pass

    def do_add_user_to_group(self, line):
        pass

    def do_change_password(self, line):
        pass

    def do_clear_rbcd(self, computer_name):

        pass

    def do_dump(self, line):
        pass

    def do_start_tls(self, line):
        pass

    def do_disable_account(self, username):
        pass

    def do_enable_account(self, username):
        pass

    def toggle_account_enable_disable(self, user_name, enable):
        pass

    def do_search(self, line):
        pass

    def do_set_dontreqpreauth(self, line):
        pass

    def do_get_user_groups(self, user_name):
        pass

    def do_get_group_users(self, group_name):
        pass

    def do_get_laps_password(self, computer_name):

        pass

    def do_grant_control(self, line):
        pass

    def do_set_rbcd(self, line):
        pass

    def do_set_shadow_creds(self, line):
        pass

    def do_clear_shadow_creds(self, target):
        pass

    def search(self, query, *attributes):
        self.client.search(self.domain_dumper.root, query, attributes=attributes)
        for entry in self.client.entries:
            print(entry.entry_dn)
            for attribute in attributes:
                value = entry[attribute].value
                if value:
                    print("%s: %s" % (attribute, entry[attribute].value))
            if any(attributes):
                print("---")

    def get_dn(self, sam_name):
        pass

    def do_whoami(self, line):
        pass

    def do_dirsync(self, line):
        pass

    def do_exit(self, line):
        pass

    def do_help(self, line):
        pass

    def do_EOF(self, line):
        pass
