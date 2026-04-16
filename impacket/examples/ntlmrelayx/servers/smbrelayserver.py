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
#   SMB Relay Server
#
#   This is the SMB server which relays the connections
#   to other protocols
#
# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
from __future__ import division
from __future__ import print_function
from threading import Thread
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import struct
import logging
import time
import calendar
import random
import string
import socket
import ntpath

from binascii import hexlify, unhexlify
from six import b
from impacket import smb, ntlm, LOG, smb3
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_ACCESS_DENIED, STATUS_SUCCESS, STATUS_NETWORK_SESSION_EXPIRED, STATUS_BAD_NETWORK_NAME
from impacket.spnego import SPNEGO_NegTokenResp, SPNEGO_NegTokenInit, TypesMech
from impacket.smbserver import SMBSERVER, outputToJohnFormat, writeJohnOutputToFile
from impacket.spnego import ASN1_AID, MechTypes, ASN1_SUPPORTED_MECH
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.smbserver import decodeSMBString, encodeSMBString
from impacket.smb3structs import SMB2Error

def auth_callback(smbServer, connData, domain_name, user_name, host_name):
    pass


class SMBRelayServer(Thread):
    def __init__(self,config):
        Thread.__init__(self)
        self.daemon = True
        self.server = 0
        #Config object
        self.config = config
        #Current target IP
        self.target = None
        #Targets handler
        self.targetprocessor = self.config.target
        #Username we auth as gets stored here later
        self.authUser = None
        self.proxyTranslator = None


        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file','None')
        smbConfig.set('global','credentials_file','')

        if self.config.smb2support is True:
            smbConfig.set("global", "SMB2Support", "True")
        else:
            smbConfig.set("global", "SMB2Support", "False")

        smbConfig.set("global", "anonymous_logon", "False")

        if self.config.outputFile is not None:
            smbConfig.set('global','jtr_dump_path',self.config.outputFile)

        if self.config.dumpHashes is True:
            smbConfig.set("global", "dump_hashes", "True")
        else:
            smbConfig.set("global", "dump_hashes", "False")
        
        if self.config.SMBServerChallenge is not None:
            smbConfig.set('global', 'challenge', self.config.SMBServerChallenge)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path','')

        # changed to dereference configuration interfaceIp
        if self.config.listeningPort:
            smbport = self.config.listeningPort
        else:
            smbport = 445

        self.server = SMBSERVER((config.interfaceIp,smbport), config_parser=smbConfig, ipv6=self.config.ipv6)
        if not self.config.disableMulti:
            self.server.setAuthCallback(auth_callback)
        logging.getLogger('impacket.smbserver').setLevel(logging.CRITICAL)

        self.server.processConfigFile()

        self.origSmbComNegotiate = self.server.hookSmbCommand(smb.SMB.SMB_COM_NEGOTIATE, self.SmbComNegotiate)
        self.origSmbSessionSetupAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX, self.SmbSessionSetupAndX)
        self.origsmbComTreeConnectAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX, self.smbComTreeConnectAndX)

        self.origSmbNegotiate = self.server.hookSmb2Command(smb3.SMB2_NEGOTIATE, self.SmbNegotiate)
        self.origSmbSessionSetup = self.server.hookSmb2Command(smb3.SMB2_SESSION_SETUP, self.SmbSessionSetup)
        self.origsmb2TreeConnect = self.server.hookSmb2Command(smb3.SMB2_TREE_CONNECT, self.smb2TreeConnect)
        # Let's use the SMBServer Connection dictionary to keep track of our client connections as well
        #TODO: See if this is the best way to accomplish this

        # changed to dereference configuration interfaceIp
        self.server.addConnection('SMBRelay', config.interfaceIp, 445)

    ### SMBv2 Part #################################################################
    def SmbNegotiate(self, connId, smbServer, recvPacket, isSMB1=False):
        pass


    def SmbSessionSetup(self, connId, smbServer, recvPacket):
        pass

    def smb2TreeConnect(self, connId, smbServer, recvPacket):
        pass

    ################################################################################

    ### SMBv1 Part #################################################################
    def SmbComNegotiate(self, connId, smbServer, SMBCommand, recvPacket):
        pass
        #############################################################

    def SmbSessionSetupAndX(self, connId, smbServer, SMBCommand, recvPacket):

        pass

    def smbComTreeConnectAndX(self, connId, smbServer, SMBCommand, recvPacket):
        pass
    ################################################################################

    #Initialize the correct client for the relay target
    def init_client(self,extSec):
        if self.target.scheme.upper() in self.config.protocolClients:
            client = self.config.protocolClients[self.target.scheme.upper()](self.config, self.target, extendedSecurity = extSec)
            if not client.initConnection():
                raise Exception('Could not initialize connection')
        else:
            raise Exception('Protocol Client for %s not found!' % self.target.scheme)


        return client

    def do_ntlm_negotiate(self,client,token):
        #Since the clients all support the same operations there is no target protocol specific code needed for now
        return client.sendNegotiate(token)

    def do_ntlm_auth(self,client,SPNEGO_token,challenge):
        #The NTLM blob is packed in a SPNEGO packet, extract it for methods other than SMB
        clientResponse, errorCode = client.sendAuth(SPNEGO_token, challenge)

        return clientResponse, errorCode

    def do_attack(self,client):
        #Do attack. Note that unlike the HTTP server, the config entries are stored in the current object and not in any of its properties
        # Check if SOCKS is enabled and if we support the target scheme
        if self.config.runSocks and self.target.scheme.upper() in self.config.socksServer.supportedSchemes:
            if self.config.runSocks is True:
                # Pass all the data to the socksplugins proxy
                activeConnections.put((self.target.hostname, client.targetPort, self.target.scheme.upper(),
                                       self.authUser, client, client.sessionData))
                return

        # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
        if self.target.scheme.upper() in self.config.attacks:
            # We have an attack.. go for it
            clientThread = self.config.attacks[self.target.scheme.upper()](self.config, client.session, self.authUser, self.target, client)
            clientThread.start()
        else:
            LOG.error('(SMB): No attack configured for %s' % self.target.scheme.upper())

    def _start(self):
        self.server.daemon_threads=True
        self.server.serve_forever()
        LOG.info('Shutting down SMB Server')
        self.server.server_close()

    def run(self):
        LOG.info("Setting up SMB Server on port %s" % self.server.server_address[1])
        self._start()

