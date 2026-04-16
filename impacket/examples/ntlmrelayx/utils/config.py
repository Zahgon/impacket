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
#   Config utilities
#
#   Configuration class which holds the config specified on the
#   command line, this can be passed to the tools' servers and clients
#
# Author:
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
from impacket.examples.utils import parse_credentials


class NTLMRelayxConfig:
    def __init__(self):

        self.daemon = True

        # Set the value of the interface ip address
        self.interfaceIp = None

        self.listeningPort = None

        self.domainIp = None

        self.machineAccount = None
        self.machineHashes = None
        self.target = None
        self.mode = None
        self.redirecthost = None
        self.outputFile = None
        self.dumpHashes = False
        self.attacks = None
        self.lootdir = None
        self.randomtargets = False
        self.encoding = None
        self.ipv6 = False
        self.remove_mic = False
        self.remove_sign_seal = False
        self.disableMulti = False
        self.keepRelaying = False

        self.command = None

        # WPAD options
        self.serve_wpad = False
        self.wpad_host = None
        self.wpad_auth_num = 0
        self.smb2support = False

        # SMB options
        self.exeFile = None
        self.interactive = False
        self.enumLocalAdmins = False
        self.SMBServerChallenge = None
        self.rpc_attack = None

        # RPC options
        self.rpc_mode = None
        self.rpc_use_smb = False
        self.auth_smb = ''
        self.smblmhash = None
        self.smbnthash = None
        self.port_smb = 445

        # LDAP options
        self.dumpdomain = True
        self.addda = True
        self.aclattack = True
        self.validateprivs = True
        self.escalateuser = None

        # MSSQL options
        self.queries = []
        self.database = None

        # Registered protocol clients
        self.protocolClients = {}

        # SOCKS options
        self.runSocks = False
        self.socksServer = None

        # HTTP options
        self.remove_target = False

        # WebDAV options
        self.serve_image = False

        # AD CS attack options
        self.isADCSAttack = False
        self.template = None
        self.altName = None

        # Shadow Credentials attack options
        self.IsShadowCredentialsAttack = False
        self.ShadowCredentialsPFXPassword = None
        self.ShadowCredentialsExportType = None
        self.ShadowCredentialsOutfilePath = None

        # SCCM attacks options
        self.isSCCMPoliciesAttack = False
        self.SCCMPoliciesClientname = None
        self.SCCMPoliciesSleep = None
        self.isSCCMDPAttack = False
        self.SCCMDPExtensions = None
        self.SCCMDPFiles = None

    def setSMBChallenge(self, value):
        pass

    def setSMBRPCAttack(self, value):
        pass

    def setSMB2Support(self, value):
        pass

    def setProtocolClients(self, clients):
        pass

    def setInterfaceIp(self, ip):
        pass

    def setListeningPort(self, port):
        pass

    def setRunSocks(self, socks, server):
        pass

    def setOutputFile(self, outputFile):
        pass

    def setdumpHashes(self, dumpHashes):
        pass

    def setTargets(self, target):
        pass

    def setExeFile(self, filename):
        pass

    def setCommand(self, command):
        pass

    def setEnumLocalAdmins(self, enumLocalAdmins):
        pass

    def setAddComputerSMB(self, addComputerSMB):
        pass

    def setDisableMulti(self, disableMulti):
        pass

    def setKeepRelaying(self, keepRelaying):
        pass

    def setEncoding(self, encoding):
        pass

    def setMode(self, mode):
        pass

    def setAttacks(self, attacks):
        pass

    def setLootdir(self, lootdir):
        pass

    def setRedirectHost(self, redirecthost):
        pass

    def setDomainAccount(self, machineAccount, machineHashes, domainIp):
        # Don't set this if we're not exploiting it
        pass

    def setRandomTargets(self, randomtargets):
        pass

    def setLDAPOptions(self, dumpdomain, addda, aclattack, validateprivs, escalateuser, addcomputer, delegateaccess, dumplaps, dumpgmsa, dumpadcs, sid, adddnsrecord):
        pass

    def setMSSQLOptions(self, queries):
        pass

    def setRPCOptions(self, rpc_mode, rpc_use_smb, auth_smb, hashes_smb, rpc_smb_port, icpr_ca_name):
        pass

    def setInteractive(self, interactive):
        pass

    def setIMAPOptions(self, keyword, mailbox, dump_all, dump_max):
        pass

    def setIPv6(self, use_ipv6):
        pass

    def setWpadOptions(self, wpad_host, wpad_auth_num):
        pass

    def setExploitOptions(self, remove_mic, remove_target, remove_sign_seal=False):
        pass

    def setWebDAVOptions(self, serve_image):
        pass

    def setADCSOptions(self, template):
        pass

    def setIsADCSAttack(self, isADCSAttack):
        pass

    def setIsShadowCredentialsAttack(self, IsShadowCredentialsAttack):
        pass

    def setShadowCredentialsOptions(self, ShadowCredentialsTarget, ShadowCredentialsPFXPassword, ShadowCredentialsExportType, ShadowCredentialsOutfilePath):
        pass
    
    def setIsSCCMPoliciesAttack(self, isSCCMPoliciesAttack):
        pass
    
    def setSCCMPoliciesOptions(self, sccm_policies_clientname, sccm_policies_sleep):
        pass
    
    def setIsSCCMDPAttack(self, isSCCMDPAttack):
        pass
    
    def setSCCMDPOptions(self, sccm_dp_extensions, sccm_dp_files):
        pass
            
    def setMSSQLDb(self, mssql_db):
        pass

    def setAltName(self, altName):
        pass

def parse_listening_ports(value):
    pass
