#!/usr/bin/env python
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
#   [MS-TDS] & [MC-SQLR] example.
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   Structure
#

import os
import cmd
import sys

# for "do_upload"
import hashlib
import base64
import shlex

class SQLSHELL(cmd.Cmd):
    def __init__(self, SQL, show_queries=False, tcpShell=None):
        if tcpShell is not None:
            cmd.Cmd.__init__(self, stdin=tcpShell.stdin, stdout=tcpShell.stdout)
            sys.stdout = tcpShell.stdout
            sys.stdin = tcpShell.stdin
            sys.stderr = tcpShell.stdout
            self.use_rawinput = False
            self.shell = tcpShell
        else:
            cmd.Cmd.__init__(self)
            self.shell = None

        self.sql = SQL
        self.show_queries = show_queries
        self.at = []
        self.set_prompt()
        self.intro = '[!] Press help for extra shell commands'

    def print_replies(self):
        # to condense all calls to sql.printReplies with right logger in this context
        pass

    def do_help(self, line):
        pass

    def postcmd(self, stop, line):
        pass

    def set_prompt(self):
        try:
            row = self.sql_query('select system_user + SPACE(2) + current_user as "username"', False)
            username_prompt = row[0]['username']
        except:
            username_prompt = '-'
        if self.at is not None and len(self.at) > 0:
            at_prompt = ''
            for (at, prefix) in self.at:
                at_prompt += '>' + at
            self.prompt = 'SQL %s (%s@%s)> ' % (at_prompt, username_prompt, self.sql.currentDB)
        else:
            self.prompt = 'SQL (%s@%s)> ' % (username_prompt, self.sql.currentDB)

    def do_show_query(self, s):
        pass

    def do_mask_query(self, s):
        pass

    def execute_as(self, exec_as):
        pass

    def do_exec_as_login(self, s):
        pass

    def do_exec_as_user(self, s):
        pass

    def do_use_link(self, s):
        pass

    def sql_query(self, query, show=True):
        if self.at is not None and len(self.at) > 0:
            for (linked_server, prefix) in self.at[::-1]:
                query = "EXEC ('" + prefix.replace("'", "''") + query.replace("'", "''") + "') AT " + linked_server
        if self.show_queries and show:
            print('[%%] %s' % query)
        return self.sql.sql_query(query)

    def do_shell(self, s):
        pass

    def do_download(self, line):
        pass

    def do_upload(self, line):
        pass

    def do_xp_dirtree(self, s):
        pass

    def do_xp_cmdshell(self, s):
        pass

    def do_sp_start_job(self, s):
        pass

    def do_lcd(self, s):
        pass

    def do_enable_xp_cmdshell(self, line):
        pass

    def do_disable_xp_cmdshell(self, line):
        pass

    def do_enum_links(self, line):
        pass

    def do_enable_rpc(self, s):
        """Enable RPC Out for a linked server to allow executing stored procedures remotely."""
        pass

    def do_disable_rpc(self, s):
        """Disable RPC Out for a linked server."""
        pass

    def do_enum_users(self, line):
        pass

    def do_enum_db(self, line):
        pass

    def do_enum_owner(self, line):
        pass

    def do_enum_impersonate(self, line):
        pass

    def do_enum_logins(self, line):
        pass

    def default(self, line):
        pass

    def emptyline(self):
        pass

    def do_exit(self, line):
        pass
