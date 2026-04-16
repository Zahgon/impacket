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
#   Mini shell using some of the SMB funcionality of the library
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   SMB DCE/RPC
#
from __future__ import division
from __future__ import print_function
from io import BytesIO
import sys
import time
import cmd
import os
import ntpath

from six import PY2
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket import LOG
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY
from impacket.acl import SMBFileACL

import charset_normalizer as chardet


class MiniImpacketShell(cmd.Cmd):
    def __init__(self, smbClient, tcpShell=None, outputfile=None):
        #If the tcpShell parameter is passed (used in ntlmrelayx),
        # all input and output is redirected to a tcp socket
        # instead of to stdin / stdout
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

        self.prompt = '# '
        self.smb = smbClient
        self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = smbClient.getCredentials()
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.pwd = ''
        self.share = None
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.outputfile = outputfile

    def emptyline(self):
        pass

    def precmd(self,line):
        # switch to unicode
        pass

    def onecmd(self,s):
        pass

    def do_exit(self,line):
        pass

    def do_shell(self, line):
        pass

    def do_help(self,line):
        pass

    def do_password(self, line):
        pass

    def do_open(self,line):
        pass

    def do_reconnect(self, line):
        pass
    
    def do_login(self,line):
        pass

    def do_kerberos_login(self,line):
        pass

    def do_login_hash(self,line):
        pass

    def do_logoff(self, line):
        pass

    def do_info(self, line):
        pass

    def do_who(self, line):
        pass

    def do_shares(self, line):
        pass

    def do_use(self,line):
        pass

    def complete_cd(self, text, line, begidx, endidx):
        pass

    def do_cd(self, line):
        pass

    def do_lcd(self, s):
        pass

    def do_pwd(self,line):
        pass

    def do_ls(self, wildcard, display = True):
        pass
    
    def do_lls(self, currentDir):
        pass

    def do_listFiles(self, share, ip):
        pass

    def do_tree(self, filepath):
        pass

    def do_rm(self, filename):
        pass

    def do_mkdir(self, path):
        pass

    def do_rmdir(self, path):
        pass

    def do_put(self, pathname):
        pass

    def complete_get(self, text, line, begidx, endidx, include = 1):
        # include means
        # 1 just files
        # 2 just directories
        pass

    def do_mget(self, mask):
        pass

    def do_get(self, filename):
        pass

    def complete_cat(self, text, line, begidx, endidx):
        pass
    
    def do_cat(self, filename):
        pass

    def do_close(self, line):
        pass

    def do_list_snapshots(self, line):
        pass

    def do_mount(self, line):
        pass

    def do_umount(self, mountpoint):
        pass

    def do_acl(self, line):
        pass

    def do_EOF(self, line):
        pass
