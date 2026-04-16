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
# Author:
#   Alberto Solino (@agsolino)
#
# TODO:
#   [-] Functions should return NT error codes
#   [-] Handling errors in all situations, right now it's just raising exceptions.
#   [*] Standard authentication support
#   [ ] Organize the connectionData stuff
#   [*] Add capability to send a bad user ID if the user is not authenticated,
#       right now you can ask for any command without actually being authenticated
#   [ ] PATH TRAVERSALS EVERYWHERE.. BE WARNED!
#   [ ] Check error situation (now many places assume the right data is coming)
#   [ ] Implement IPC to the main process so the connectionData is on a single place
#   [ ] Hence.. implement locking
# estamos en la B

import calendar
import socket
import time
import datetime
import struct
import threading
import logging
import logging.config
import ntpath
import os
import fnmatch
import errno
import sys
import random
import shutil
import string
import hashlib
import hmac

from binascii import unhexlify, hexlify, a2b_hex
from impacket.dcerpc.v5 import epm, nrpc, transport
from impacket.dcerpc.v5 import rpcrt
from six import b, ensure_str
from six.moves import configparser, socketserver
from pyasn1.codec.der import encoder, decoder

# For signing
from impacket import smb, nmb, ntlm, uuid
from impacket import smb3structs as smb2
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, MechTypes, SPNEGO_NegTokenResp, ASN1_AID, \
    ASN1_SUPPORTED_MECH
from impacket.krb5.asn1 import AP_REP, Authenticator, EncAPRepPart, EncTicketPart, GSSAPIHeader_KRB5_AP_REQ
from impacket.krb5 import constants
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum, generate_kerberos_keys
from impacket.nt_errors import STATUS_NO_MORE_FILES, STATUS_NETWORK_NAME_DELETED, STATUS_INVALID_PARAMETER, \
    STATUS_FILE_CLOSED, STATUS_MORE_PROCESSING_REQUIRED, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_DIRECTORY_NOT_EMPTY, \
    STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_IMPLEMENTED, STATUS_INVALID_HANDLE, STATUS_OBJECT_NAME_COLLISION, \
    STATUS_NO_SUCH_FILE, STATUS_CANCELLED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS, STATUS_ACCESS_DENIED, \
    STATUS_NOT_SUPPORTED, STATUS_INVALID_DEVICE_REQUEST, STATUS_FS_DRIVER_REQUIRED, STATUS_INVALID_INFO_CLASS, \
    STATUS_LOGON_FAILURE, STATUS_OBJECT_PATH_SYNTAX_BAD, STATUS_END_OF_FILE

# Setting LOG to current's module name
LOG = logging.getLogger(__name__)

# These ones not defined in nt_errors
STATUS_SMB_BAD_UID = 0x005B0002
STATUS_SMB_BAD_TID = 0x00050002


# Utility functions
# and general functions.
# There are some common functions that can be accessed from more than one SMB
# command (or either TRANSACTION). That's why I'm putting them here
# TODO: Return NT ERROR Codes

def getFileTime(t):
    pass

def getUnixTime(t):
    return smb.FTtoPOSIX(t)

def computeNTLMv2(identity, lmhash, nthash, serverChallenge, authenticateMessage, ntlmChallenge, type1):
    # Let's calculate the NTLMv2 Response

    pass


def outputToJohnFormat(challenge, username, domain, lmresponse, ntresponse):
    # We don't want to add a possible failure here, since this is an
    # extra bonus. We try, if it fails, returns nothing
    # ToDo: Document the parameter's types (bytes / string) and check all the places where it's called
    ret_value = ''
    if type(challenge) is not bytes:
        challenge = challenge.decode('latin-1')

    try:
        if len(ntresponse) > 24:
            # Extended Security - NTLMv2
            ret_value = {'hash_string': '%s::%s:%s:%s:%s' % (
                username.decode('utf-16le'), domain.decode('utf-16le'), hexlify(challenge).decode('latin-1'),
                hexlify(ntresponse).decode('latin-1')[:32],
                hexlify(ntresponse).decode()[32:]), 'hash_version': 'ntlmv2'}
        else:
            # NTLMv1
            ret_value = {'hash_string': '%s::%s:%s:%s:%s' % (
                username.decode('utf-16le'), domain.decode('utf-16le'), hexlify(lmresponse).decode('latin-1'),
                hexlify(ntresponse).decode('latin-1'),
                hexlify(challenge).decode()), 'hash_version': 'ntlm'}
    except:
        # Let's try w/o decoding Unicode
        try:
            if len(ntresponse) > 24:
                # Extended Security - NTLMv2
                ret_value = {'hash_string': '%s::%s:%s:%s:%s' % (
                    username.decode('latin-1'), domain.decode('latin-1'), hexlify(challenge).decode('latin-1'),
                    hexlify(ntresponse)[:32].decode('latin-1'), hexlify(ntresponse)[32:].decode('latin-1')),
                             'hash_version': 'ntlmv2'}
            else:
                # NTLMv1
                ret_value = {'hash_string': '%s::%s:%s:%s:%s' % (
                    username, domain, hexlify(lmresponse).decode('latin-1'), hexlify(ntresponse).decode('latin-1'),
                    hexlify(challenge).decode('latin-1')), 'hash_version': 'ntlm'}
        except Exception as e:
            import traceback
            traceback.print_exc()
            LOG.error("outputToJohnFormat: %s" % e)
            pass

    return ret_value


def writeJohnOutputToFile(hash_string, hash_version, file_name):
    fn_data = os.path.splitext(file_name)
    if hash_version == "ntlmv2":
        output_filename = fn_data[0] + "_ntlmv2" + fn_data[1]
    else:
        output_filename = fn_data[0] + "_ntlm" + fn_data[1]

    with open(output_filename, "a") as f:
        f.write(hash_string)
        f.write('\n')


def decodeSMBString(flags, text):
    if flags & smb.SMB.FLAGS2_UNICODE:
        return text.decode('utf-16le')
    else:
        return text


def encodeSMBString(flags, text):
    if flags & smb.SMB.FLAGS2_UNICODE:
        return (text).encode('utf-16le')
    else:
        return text.encode('ascii')


def getSMBDate(t):
    pass


def getSMBTime(t):
    pass


def getShares(connId, smbServer):
    config = smbServer.getServerConfig()
    sections = config.sections()
    # Remove the global one
    del (sections[sections.index('global')])
    shares = {}
    for i in sections:
        shares[i] = dict(config.items(i))
    return shares


def searchShare(connId, share, smbServer):
    pass


def normalize_path(file_name, path=None):
    """Normalizes a path by replacing "\" with "/" and stripping potential
    leading "/" chars. If a path is provided, only strip leading '/' when
    the path is empty.

    :param file_name: file name to normalize
    :type file_name: string

    :param path: path to normalize
    :type path: string

    :return normalized file name
    :rtype string
    """
    file_name = os.path.normpath(file_name.replace('\\', '/'))
    if len(file_name) > 0 and (file_name[0] == '/' or file_name[0] == '\\'):
        if path is None or path != '':
            # Strip leading "/"
            file_name = file_name[1:]
    return file_name


def isInFileJail(path, file_name):
    """Validates if a provided file name path is inside a path. This function is used
    to check for path traversals.

    :param path: base path to check
    :type path: string
    :param file_name: file name to validate
    :type file_name: string

    :return whether the file name is inside the base path or not
    :rtype bool
    """
    path_name = os.path.join(path, file_name)
    share_real_path = os.path.realpath(path)
    return os.path.commonprefix((os.path.realpath(path_name), share_real_path)) == share_real_path


def openFile(path, fileName, accessMode, fileAttributes, openMode, readOnly):
    fileName = normalize_path(fileName)
    pathName = os.path.join(path, fileName)
    errorCode = 0
    mode = 0

    if not isInFileJail(path, fileName):
        LOG.error("Path not in current working directory")
        errorCode = STATUS_OBJECT_PATH_SYNTAX_BAD
        return 0, mode, pathName, errorCode

    # Check the Open Mode
    if openMode & 0x10:
        # If the file does not exist, create it.
        mode = os.O_CREAT
    else:
        # If file does not exist, return an error
        if os.path.exists(pathName) is not True:
            errorCode = STATUS_NO_SUCH_FILE
            return 0, mode, pathName, errorCode

    if os.path.isdir(pathName) and (fileAttributes & smb.ATTR_DIRECTORY) == 0:
        # Request to open a normal file and this is actually a directory
        errorCode = STATUS_FILE_IS_A_DIRECTORY
        return 0, mode, pathName, errorCode
    # Check the Access Mode
    if accessMode & 0x7 == 1:
        mode |= os.O_WRONLY
    elif accessMode & 0x7 == 2:
        mode |= os.O_RDWR
    else:
        mode = os.O_RDONLY

    try:
        if sys.platform == 'win32':
            mode |= os.O_BINARY
        if readOnly:
            mode = os.O_RDONLY
        fid = os.open(pathName, mode)
    except Exception as e:
        LOG.error("openFile: %s,%s" % (pathName, mode), e)
        fid = 0
        errorCode = STATUS_ACCESS_DENIED

    return fid, mode, pathName, errorCode


def queryFsInformation(path, filename, level=None, pktFlags=smb.SMB.FLAGS2_UNICODE):
    pass


def findFirst2(path, fileName, level, searchAttributes, pktFlags=smb.SMB.FLAGS2_UNICODE, isSMB2=False):
    # TODO: Depending on the level, this could be done much simpler

    # Let's choose the right encoding depending on the request
    pass


def queryFileInformation(path, filename, level):
    # print "queryFileInfo path: %s, filename: %s, level:0x%x" % (path,filename,level)
    pass


def queryPathInformation(path, filename, level):
    # TODO: Depending on the level, this could be done much simpler
    pass


def queryDiskInformation(path):
    # TODO: Do something useful here :)
    # For now we just return fake values
    pass


# Here we implement the NT transaction handlers
class NTTRANSCommands:
    def default(self, connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        pass


# Here we implement the NT transaction handlers
class TRANSCommands:
    @staticmethod
    def lanMan(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        # Minimal [MS-RAP] implementation, just to return the shares
        pass

    @staticmethod
    def transactNamedPipe(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        pass


# Here we implement the transaction2 handlers
class TRANS2Commands:
    # All these commands return setup, parameters, data, errorCode

    @staticmethod
    def setPathInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        pass

    @staticmethod
    def setFileInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        pass

    @staticmethod
    def queryFileInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        pass

    @staticmethod
    def queryPathInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        pass

    @staticmethod
    def queryFsInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        pass

    @staticmethod
    def findNext2(connId, smbServer, recvPacket, parameters, data, maxDataCount):
        pass

    @staticmethod
    def findFirst2(connId, smbServer, recvPacket, parameters, data, maxDataCount):
        pass


# Here we implement the commands handlers
class SMBCommands:

    @staticmethod
    def smbTransaction(connId, smbServer, SMBCommand, recvPacket, transCommands):
        pass

    @staticmethod
    def smbNTTransact(connId, smbServer, SMBCommand, recvPacket, transCommands):
        pass

    @staticmethod
    def smbTransaction2(connId, smbServer, SMBCommand, recvPacket, transCommands):
        pass

    @staticmethod
    def smbComLockingAndX(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComClose(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComWrite(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComFlush(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComCreateDirectory(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComRename(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComDelete(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComDeleteDirectory(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComWriteAndX(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComRead(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComReadAndX(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbQueryInformation(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbQueryInformationDisk(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComEcho(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComTreeDisconnect(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComLogOffAndX(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComQueryInformation2(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComNtCreateAndX(connId, smbServer, SMBCommand, recvPacket):
        # TODO: Fully implement this
        pass

    @staticmethod
    def smbComOpenAndX(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComTreeConnectAndX(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComSessionSetupAndX(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def smbComNegotiate(connId, smbServer, SMBCommand, recvPacket):
        pass

    @staticmethod
    def default(connId, smbServer, SMBCommand, recvPacket):
        # By default we return an SMB Packet with error not implemented
        pass


class SMB2Commands:
    @staticmethod
    def smb2Negotiate(connId, smbServer, recvPacket, isSMB1=False):
        pass

    @staticmethod
    def _kerberos_auth(token, connData, smbServer):
        pass
        
    @staticmethod
    def _ntlm_auth(token, connData, smbServer, rawNTLM):
        # Here we only handle NTLMSSP, depending on what stage of the
        # authentication we are, we act on it
        pass

    @staticmethod
    def generic_negTokenResp():
        pass

    @staticmethod
    def smb2SessionSetup(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2TreeConnect(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2Create(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2Close(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2QueryInfo(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2SetInfo(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2Write(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2Read(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2Flush(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2QueryDirectory(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2ChangeNotify(connId, smbServer, recvPacket):

        pass

    @staticmethod
    def smb2Echo(connId, smbServer, recvPacket):

        pass

    @staticmethod
    def smb2TreeDisconnect(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2Logoff(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2Ioctl(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2Lock(connId, smbServer, recvPacket):
        pass

    @staticmethod
    def smb2Cancel(connId, smbServer, recvPacket):
        # I'm actually doing nothing
        pass

    @staticmethod
    def default(connId, smbServer, recvPacket):
        # By default we return an SMB Packet with error not implemented
        pass


class Ioctls:
    @staticmethod
    def fsctlDfsGetReferrals(connId, smbServer, ioctlRequest):
        pass

    @staticmethod
    def fsctlPipeTransceive(connId, smbServer, ioctlRequest):
        pass

    @staticmethod
    def fsctlValidateNegotiateInfo(connId, smbServer, ioctlRequest):
        pass


class SMBSERVERHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server, select_poll=False):
        self.__SMB = server
        # In case of AF_INET6 the client_address contains 4 items, ignore the last 2
        self.__ip, self.__port = client_address[:2]
        self.__request = request
        self.__connId = threading.current_thread().name
        self.__timeOut = 60 * 5
        self.__select_poll = select_poll
        # self.__connId = os.getpid()
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        self.__SMB.log("Incoming connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.addConnection(self.__connId, self.__ip, self.__port)
        while True:
            try:
                # First of all let's get the NETBIOS packet
                session = nmb.NetBIOSTCPSession(self.__SMB.getServerName(), 'HOST', self.__ip, sess_port=self.__port,
                                                sock=self.__request, select_poll=self.__select_poll)
                try:
                    p = session.recv_packet(self.__timeOut)
                except nmb.NetBIOSTimeout:
                    raise
                except nmb.NetBIOSError:
                    break

                if p.get_type() == nmb.NETBIOS_SESSION_REQUEST:
                    # Someone is requesting a session, we're gonna accept them all :)
                    _, rn, my = p.get_trailer().split(b' ')
                    remote_name = nmb.decode_name(b'\x20' + rn)
                    myname = nmb.decode_name(b'\x20' + my)
                    self.__SMB.log(
                        "NetBIOS Session request (%s,%s,%s)" % (self.__ip, remote_name[1].strip(), myname[1]))
                    r = nmb.NetBIOSSessionPacket()
                    r.set_type(nmb.NETBIOS_SESSION_POSITIVE_RESPONSE)
                    r.set_trailer(p.get_trailer())
                    self.__request.send(r.rawData())
                else:
                    resp = self.__SMB.processRequest(self.__connId, p.get_trailer())
                    # Send all the packets received. Except for big transactions this should be
                    # a single packet
                    for i in resp:
                        if hasattr(i, 'getData'):
                            session.send_packet(i.getData())
                        else:
                            session.send_packet(i)
            except Exception as e:
                self.__SMB.log("Handle: %s" % e)
                import traceback
                traceback.print_exc()
                break

    def finish(self):
        # Thread/process is dying, we should tell the main SMB thread to remove all this thread data
        self.__SMB.log("Closing down connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.removeConnection(self.__connId)
        return socketserver.BaseRequestHandler.finish(self)


class SMBSERVER(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # class SMBSERVER(socketserver.ForkingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, handler_class=SMBSERVERHandler, config_parser=None, ipv6=False):
        # duplicate of https://github.com/fortra/impacket/blob/082dca34a376d13c70b0df6a1d9048ce98fe9498/impacket/examples/utils.py#L323
        # didn't reuse that same function in order not to make a class from the library depend on one from impacket/examples
        if ipv6:
            self.address_family = socket.AF_INET6
            # scope_id (after %) can be present or not - if not, default: 0
            ip_parts = server_address[0].split('%')
            scope_id = ip_parts[1] if len(ip_parts) == 2 else 0
            # convert scope_id to int (expected by s.connect)
            # if exception, assume the interface name and convert to index
            try:
                scope_id = int(scope_id)
            except ValueError:
                scope_id = socket.if_nametoindex(scope_id)
            server_address = server_address + (0, scope_id)

        socketserver.TCPServer.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, server_address, handler_class)

        # Server name and OS to be presented whenever is necessary
        self.__serverName = ''
        self.__serverOS = ''
        self.__serverDomain = ''
        self.__challenge = ''
        self.__log = None

        self.__computerAccountName = ''
        self.__computerAccountNTHash = ''
        self.__computerAccountAES = ''
        self.__computerAccountPassword = ''
        self.__computerAccountDomain = ''
        self.__domainControllerIP = ''

        # Our ConfigParser data
        self.__serverConfig = config_parser

        # Our credentials to be used during the server's lifetime
        self.__credentials = {}

        # Our log file
        self.__logFile = ''

        # Registered Named Pipes, format is PipeName,Socket
        self.__registeredNamedPipes = {}

        # JTR dump path
        self.__jtr_dump_path = ''

        # SMB2 Support flag = default not active
        self.__SMB2Support = False

        self.__dropSSP = False
        # Kerberos Support flag
        self.__KerberosSupport = False

        # NTLM Support flag
        self.__NTLMSupport = True

        # Allow anonymous logon
        self.__anonymousLogon = True

        self.auth_callback = None

        # Our list of commands we will answer, by default the NOT IMPLEMENTED one
        self.__smbCommandsHandler = SMBCommands()
        self.__smbTrans2Handler = TRANS2Commands()
        self.__smbTransHandler = TRANSCommands()
        self.__smbNTTransHandler = NTTRANSCommands()
        self.__smb2CommandsHandler = SMB2Commands()
        self.__IoctlHandler = Ioctls()

        self.__smbNTTransCommands = {
            # NT IOCTL, can't find doc for this
            0xff: self.__smbNTTransHandler.default
        }

        self.__smbTransCommands = {
            '\\PIPE\\LANMAN': self.__smbTransHandler.lanMan,
            smb.SMB.TRANS_TRANSACT_NMPIPE: self.__smbTransHandler.transactNamedPipe,
        }
        self.__smbTrans2Commands = {
            smb.SMB.TRANS2_FIND_FIRST2: self.__smbTrans2Handler.findFirst2,
            smb.SMB.TRANS2_FIND_NEXT2: self.__smbTrans2Handler.findNext2,
            smb.SMB.TRANS2_QUERY_FS_INFORMATION: self.__smbTrans2Handler.queryFsInformation,
            smb.SMB.TRANS2_QUERY_PATH_INFORMATION: self.__smbTrans2Handler.queryPathInformation,
            smb.SMB.TRANS2_QUERY_FILE_INFORMATION: self.__smbTrans2Handler.queryFileInformation,
            smb.SMB.TRANS2_SET_FILE_INFORMATION: self.__smbTrans2Handler.setFileInformation,
            smb.SMB.TRANS2_SET_PATH_INFORMATION: self.__smbTrans2Handler.setPathInformation
        }

        self.__smbCommands = {
            smb.SMB.SMB_COM_FLUSH: self.__smbCommandsHandler.smbComFlush,
            smb.SMB.SMB_COM_CREATE_DIRECTORY: self.__smbCommandsHandler.smbComCreateDirectory,
            smb.SMB.SMB_COM_DELETE_DIRECTORY: self.__smbCommandsHandler.smbComDeleteDirectory,
            smb.SMB.SMB_COM_RENAME: self.__smbCommandsHandler.smbComRename,
            smb.SMB.SMB_COM_DELETE: self.__smbCommandsHandler.smbComDelete,
            smb.SMB.SMB_COM_NEGOTIATE: self.__smbCommandsHandler.smbComNegotiate,
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX: self.__smbCommandsHandler.smbComSessionSetupAndX,
            smb.SMB.SMB_COM_LOGOFF_ANDX: self.__smbCommandsHandler.smbComLogOffAndX,
            smb.SMB.SMB_COM_TREE_CONNECT_ANDX: self.__smbCommandsHandler.smbComTreeConnectAndX,
            smb.SMB.SMB_COM_TREE_DISCONNECT: self.__smbCommandsHandler.smbComTreeDisconnect,
            smb.SMB.SMB_COM_ECHO: self.__smbCommandsHandler.smbComEcho,
            smb.SMB.SMB_COM_QUERY_INFORMATION: self.__smbCommandsHandler.smbQueryInformation,
            smb.SMB.SMB_COM_TRANSACTION2: self.__smbCommandsHandler.smbTransaction2,
            smb.SMB.SMB_COM_TRANSACTION: self.__smbCommandsHandler.smbTransaction,
            # Not needed for now
            smb.SMB.SMB_COM_NT_TRANSACT: self.__smbCommandsHandler.smbNTTransact,
            smb.SMB.SMB_COM_QUERY_INFORMATION_DISK: self.__smbCommandsHandler.smbQueryInformationDisk,
            smb.SMB.SMB_COM_OPEN_ANDX: self.__smbCommandsHandler.smbComOpenAndX,
            smb.SMB.SMB_COM_QUERY_INFORMATION2: self.__smbCommandsHandler.smbComQueryInformation2,
            smb.SMB.SMB_COM_READ_ANDX: self.__smbCommandsHandler.smbComReadAndX,
            smb.SMB.SMB_COM_READ: self.__smbCommandsHandler.smbComRead,
            smb.SMB.SMB_COM_WRITE_ANDX: self.__smbCommandsHandler.smbComWriteAndX,
            smb.SMB.SMB_COM_WRITE: self.__smbCommandsHandler.smbComWrite,
            smb.SMB.SMB_COM_CLOSE: self.__smbCommandsHandler.smbComClose,
            smb.SMB.SMB_COM_LOCKING_ANDX: self.__smbCommandsHandler.smbComLockingAndX,
            smb.SMB.SMB_COM_NT_CREATE_ANDX: self.__smbCommandsHandler.smbComNtCreateAndX,
            0xFF: self.__smbCommandsHandler.default
        }

        self.__smb2Ioctls = {
            smb2.FSCTL_DFS_GET_REFERRALS: self.__IoctlHandler.fsctlDfsGetReferrals,
            # smb2.FSCTL_PIPE_PEEK:                    self.__IoctlHandler.fsctlPipePeek,
            # smb2.FSCTL_PIPE_WAIT:                    self.__IoctlHandler.fsctlPipeWait,
            smb2.FSCTL_PIPE_TRANSCEIVE: self.__IoctlHandler.fsctlPipeTransceive,
            # smb2.FSCTL_SRV_COPYCHUNK:                self.__IoctlHandler.fsctlSrvCopyChunk,
            # smb2.FSCTL_SRV_ENUMERATE_SNAPSHOTS:      self.__IoctlHandler.fsctlSrvEnumerateSnapshots,
            # smb2.FSCTL_SRV_REQUEST_RESUME_KEY:       self.__IoctlHandler.fsctlSrvRequestResumeKey,
            # smb2.FSCTL_SRV_READ_HASH:                self.__IoctlHandler.fsctlSrvReadHash,
            # smb2.FSCTL_SRV_COPYCHUNK_WRITE:          self.__IoctlHandler.fsctlSrvCopyChunkWrite,
            # smb2.FSCTL_LMR_REQUEST_RESILIENCY:       self.__IoctlHandler.fsctlLmrRequestResiliency,
            # smb2.FSCTL_QUERY_NETWORK_INTERFACE_INFO: self.__IoctlHandler.fsctlQueryNetworkInterfaceInfo,
            # smb2.FSCTL_SET_REPARSE_POINT:            self.__IoctlHandler.fsctlSetReparsePoint,
            # smb2.FSCTL_DFS_GET_REFERRALS_EX:         self.__IoctlHandler.fsctlDfsGetReferralsEx,
            # smb2.FSCTL_FILE_LEVEL_TRIM:              self.__IoctlHandler.fsctlFileLevelTrim,
            smb2.FSCTL_VALIDATE_NEGOTIATE_INFO: self.__IoctlHandler.fsctlValidateNegotiateInfo,
        }

        self.__smb2Commands = {
            smb2.SMB2_NEGOTIATE: self.__smb2CommandsHandler.smb2Negotiate,
            smb2.SMB2_SESSION_SETUP: self.__smb2CommandsHandler.smb2SessionSetup,
            smb2.SMB2_LOGOFF: self.__smb2CommandsHandler.smb2Logoff,
            smb2.SMB2_TREE_CONNECT: self.__smb2CommandsHandler.smb2TreeConnect,
            smb2.SMB2_TREE_DISCONNECT: self.__smb2CommandsHandler.smb2TreeDisconnect,
            smb2.SMB2_CREATE: self.__smb2CommandsHandler.smb2Create,
            smb2.SMB2_CLOSE: self.__smb2CommandsHandler.smb2Close,
            smb2.SMB2_FLUSH: self.__smb2CommandsHandler.smb2Flush,
            smb2.SMB2_READ: self.__smb2CommandsHandler.smb2Read,
            smb2.SMB2_WRITE: self.__smb2CommandsHandler.smb2Write,
            smb2.SMB2_LOCK: self.__smb2CommandsHandler.smb2Lock,
            smb2.SMB2_IOCTL: self.__smb2CommandsHandler.smb2Ioctl,
            smb2.SMB2_CANCEL: self.__smb2CommandsHandler.smb2Cancel,
            smb2.SMB2_ECHO: self.__smb2CommandsHandler.smb2Echo,
            smb2.SMB2_QUERY_DIRECTORY: self.__smb2CommandsHandler.smb2QueryDirectory,
            smb2.SMB2_CHANGE_NOTIFY: self.__smb2CommandsHandler.smb2ChangeNotify,
            smb2.SMB2_QUERY_INFO: self.__smb2CommandsHandler.smb2QueryInfo,
            smb2.SMB2_SET_INFO: self.__smb2CommandsHandler.smb2SetInfo,
            # smb2.SMB2_OPLOCK_BREAK:    self.__smb2CommandsHandler.smb2SessionSetup,
            0xFF: self.__smb2CommandsHandler.default
        }

        # List of active connections
        self.__activeConnections = {}

    def getIoctls(self):
        pass

    def getCredentials(self):
        return self.__credentials

    def removeConnection(self, name):
        try:
            del (self.__activeConnections[name])
        except:
            pass
        self.log("Remaining connections %s" % list(self.__activeConnections.keys()))

    def addConnection(self, name, ip, port):
        self.__activeConnections[name] = {}
        # Let's init with some know stuff we will need to have
        # TODO: Document what's in there
        # print "Current Connections", self.__activeConnections.keys()
        self.__activeConnections[name]['PacketNum'] = 0
        self.__activeConnections[name]['ClientIP'] = ip
        self.__activeConnections[name]['ClientPort'] = port
        self.__activeConnections[name]['Uid'] = 0
        self.__activeConnections[name]['ConnectedShares'] = {}
        self.__activeConnections[name]['OpenedFiles'] = {}
        # SID results for findfirst2
        self.__activeConnections[name]['SIDs'] = {}
        self.__activeConnections[name]['LastRequest'] = {}
        self.__activeConnections[name]['SignatureEnabled'] = False
        self.__activeConnections[name]['SigningChallengeResponse'] = ''
        self.__activeConnections[name]['SigningSessionKey'] = b''
        self.__activeConnections[name]['Authenticated'] = False

    def getActiveConnections(self):
        pass

    def setConnectionData(self, connId, data):
        self.__activeConnections[connId] = data
        # print "setConnectionData"
        # print self.__activeConnections

    def getConnectionData(self, connId, checkStatus=True):
        conn = self.__activeConnections[connId]
        if checkStatus is True:
            if ('Authenticated' in conn) is not True:
                # Can't keep going further
                raise Exception("User not Authenticated!")
        return conn

    def getRegisteredNamedPipes(self):
        pass

    def registerNamedPipe(self, pipeName, address):
        self.__registeredNamedPipes[str(pipeName)] = address
        return True

    def unregisterNamedPipe(self, pipeName):
        pass

    def unregisterTransaction(self, transCommand):
        pass

    def hookTransaction(self, transCommand, callback):
        # If you call this function, callback will replace
        # the current Transaction sub command.
        # (don't get confused with the Transaction smbCommand)
        # If the transaction sub command doesn't not exist, it is added
        # If the transaction sub command exists, it returns the original function         # replaced
        #
        # callback MUST be declared as:
        # callback(connId, smbServer, recvPacket, parameters, data, maxDataCount=0)
        #
        # WHERE:
        #
        # connId      : the connection Id, used to grab/update information about
        #               the current connection
        # smbServer   : the SMBServer instance available for you to ask
        #               configuration data
        # recvPacket  : the full SMBPacket that triggered this command
        # parameters  : the transaction parameters
        # data        : the transaction data
        # maxDataCount: the max amount of data that can be transferred agreed
        #               with the client
        #
        # and MUST return:
        # respSetup, respParameters, respData, errorCode
        #
        # WHERE:
        #
        # respSetup: the setup response of the transaction
        # respParameters: the parameters response of the transaction
        # respData: the data response of the transaction
        # errorCode: the NT error code

        pass

    def unregisterTransaction2(self, transCommand):
        pass

    def hookTransaction2(self, transCommand, callback):
        # Here we should add to __smbTrans2Commands
        # Same description as Transaction
        pass

    def unregisterNTTransaction(self, transCommand):
        pass

    def hookNTTransaction(self, transCommand, callback):
        # Here we should add to __smbNTTransCommands
        # Same description as Transaction
        pass

    def unregisterSmbCommand(self, smbCommand):
        pass

    def hookSmbCommand(self, smbCommand, callback):
        # Here we should add to self.__smbCommands
        # If you call this function, callback will replace
        # the current smbCommand.
        # If smbCommand doesn't not exist, it is added
        # If SMB command exists, it returns the original function replaced
        #
        # callback MUST be declared as:
        # callback(connId, smbServer, SMBCommand, recvPacket)
        #
        # WHERE:
        #
        # connId    : the connection Id, used to grab/update information about
        #             the current connection
        # smbServer : the SMBServer instance available for you to ask
        #             configuration data
        # SMBCommand: the SMBCommand itself, with its data and parameters.
        #             Check smb.py:SMBCommand() for a reference
        # recvPacket: the full SMBPacket that triggered this command
        #
        # and MUST return:
        # <list of respSMBCommands>, <list of packets>, errorCode
        # <list of packets> has higher preference over commands, in case you
        # want to change the whole packet
        # errorCode: the NT error code
        #
        # For SMB_COM_TRANSACTION2, SMB_COM_TRANSACTION and SMB_COM_NT_TRANSACT
        # the callback function is slightly different:
        #
        # callback(connId, smbServer, SMBCommand, recvPacket, transCommands)
        #
        # WHERE:
        #
        # transCommands: a list of transaction subcommands already registered
        #

        if smbCommand in self.__smbCommands:
            originalCommand = self.__smbCommands[smbCommand]
        else:
            originalCommand = None

        self.__smbCommands[smbCommand] = callback
        return originalCommand

    def unregisterSmb2Command(self, smb2Command):
        pass

    def hookSmb2Command(self, smb2Command, callback):
        if smb2Command in self.__smb2Commands:
            originalCommand = self.__smb2Commands[smb2Command]
        else:
            originalCommand = None

        self.__smb2Commands[smb2Command] = callback
        return originalCommand

    def log(self, msg, level=logging.INFO, connData=None):
        if connData:
            domain = connData.get('user_domain_name') or "NULL"
            username = connData.get('user_name') or "NULL"
            msg = f"{domain}\\{username}: " + msg
        self.__log.log(level, msg)

    def getServerName(self):
        return self.__serverName

    def getServerOS(self):
        pass

    def getServerDomain(self):
        return self.__serverDomain

    def getSMBChallenge(self):
        pass

    def getServerConfig(self):
        return self.__serverConfig

    def setServerConfig(self, config):
        pass

    def getJTRdumpPath(self):
        pass

    def getDumpHashes(self):
        pass

    def getAuthCallback(self):
        pass

    def setAuthCallback(self, callback):
        self.auth_callback = callback

    def getKerberosSupport(self):
        pass

    def getNTLMSupport(self):
        pass

    def verify_request(self, request, client_address):
        # TODO: Control here the max amount of processes we want to launch
        # returning False, closes the connection
        pass

    def signSMBv1(self, connData, packet, signingSessionKey, signingChallengeResponse):
        # This logic MUST be applied for messages sent in response to any of the higher-layer actions and in
        # compliance with the message sequencing rules.
        #  * The client or server that sends the message MUST provide the 32-bit sequence number for this
        #    message, as specified in sections 3.2.4.1 and 3.3.4.1.
        #  * The SMB_FLAGS2_SMB_SECURITY_SIGNATURE flag in the header MUST be set.
        #  * To generate the signature, a 32-bit sequence number is copied into the
        #    least significant 32 bits of the SecuritySignature field and the remaining
        #    4 bytes are set to 0x00.
        #  * The MD5 algorithm, as specified in [RFC1321], MUST be used to generate a hash of the SMB
        #    message from the start of the SMB Header, which is defined as follows.
        #    CALL MD5Init( md5context )
        #    CALL MD5Update( md5context, Connection.SigningSessionKey )
        #    CALL MD5Update( md5context, Connection.SigningChallengeResponse )
        #    CALL MD5Update( md5context, SMB message )
        #    CALL MD5Final( digest, md5context )
        #    SET signature TO the first 8 bytes of the digest
        # The resulting 8-byte signature MUST be copied into the SecuritySignature field of the SMB Header,
        # after which the message can be transmitted.

        # print "seq(%d) signingSessionKey %r, signingChallengeResponse %r" % (connData['SignSequenceNumber'], signingSessionKey, signingChallengeResponse)
        packet['SecurityFeatures'] = struct.pack('<q', connData['SignSequenceNumber'])
        # Sign with the sequence
        m = hashlib.md5()
        m.update(signingSessionKey)
        m.update(signingChallengeResponse)
        if hasattr(packet, 'getData'):
            m.update(packet.getData())
        else:
            m.update(packet)
        # Replace sequence with acual hash
        packet['SecurityFeatures'] = m.digest()[:8]
        connData['SignSequenceNumber'] += 2

    def signSMBv2(self, packet, signingSessionKey, padLength=0):
        packet['Signature'] = b'\x00' * 16
        packet['Flags'] |= smb2.SMB2_FLAGS_SIGNED
        packetData = packet.getData() + b'\x00' * padLength
        signature = hmac.new(signingSessionKey, packetData, hashlib.sha256).digest()
        packet['Signature'] = signature[:16]
        # print "%s" % packet['Signature'].encode('hex')

    def processRequest(self, connId, data):

        # TODO: Process batched commands.
        isSMB2 = False
        SMBCommand = None
        try:
            packet = smb.NewSMBPacket(data=data)
            SMBCommand = smb.SMBCommand(packet['Data'][0])
        except:
            # Maybe a SMB2 packet?
            packet = smb2.SMB2Packet(data=data)
            connData = self.getConnectionData(connId, False)
            self.signSMBv2(packet, connData['SigningSessionKey'])
            isSMB2 = True

        connData = self.getConnectionData(connId, False)

        # We might have compound requests
        compoundedPacketsResponse = []
        compoundedPackets = []
        try:
            # Search out list of implemented commands
            # We provide them with:
            # connId      : representing the data for this specific connection
            # self        : the SMBSERVER if they want to ask data to it
            # SMBCommand  : the SMBCommand they are expecting to process
            # packet      : the received packet itself, in case they need more data than the actual command
            # Only for Transactions
            # transCommand: a list of transaction subcommands
            # We expect to get:
            # respCommands: a list of answers for the commands processed
            # respPacket  : if the commands chose to directly craft packet/s, we use this and not the previous
            #               this MUST be a list
            # errorCode   : self explanatory
            if isSMB2 is False:
                # Is the client authenticated already?
                if connData['Authenticated'] is False and packet['Command'] not in (
                smb.SMB.SMB_COM_NEGOTIATE, smb.SMB.SMB_COM_SESSION_SETUP_ANDX):
                    # Nope.. in that case he should only ask for a few commands, if not throw him out.
                    errorCode = STATUS_ACCESS_DENIED
                    respPackets = None
                    respCommands = [smb.SMBCommand(packet['Command'])]
                else:
                    if packet['Command'] == smb.SMB.SMB_COM_TRANSACTION2:
                        respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                            connId,
                            self,
                            SMBCommand,
                            packet,
                            self.__smbTrans2Commands)
                    elif packet['Command'] == smb.SMB.SMB_COM_NT_TRANSACT:
                        respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                            connId,
                            self,
                            SMBCommand,
                            packet,
                            self.__smbNTTransCommands)
                    elif packet['Command'] == smb.SMB.SMB_COM_TRANSACTION:
                        respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                            connId,
                            self,
                            SMBCommand,
                            packet,
                            self.__smbTransCommands)
                    else:
                        if packet['Command'] in self.__smbCommands:
                            if self.__SMB2Support is True:
                                if packet['Command'] == smb.SMB.SMB_COM_NEGOTIATE:
                                    try:
                                        respCommands, respPackets, errorCode = self.__smb2Commands[smb2.SMB2_NEGOTIATE](
                                            connId, self, packet, True)
                                        isSMB2 = True
                                    except Exception as e:
                                        import traceback
                                        traceback.print_exc()
                                        self.log('SMB2_NEGOTIATE: %s' % e, logging.ERROR)
                                        # If something went wrong, let's fallback to SMB1
                                        respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                            connId,
                                            self,
                                            SMBCommand,
                                            packet)
                                        # self.__SMB2Support = False
                                        pass
                                else:
                                    respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                        connId,
                                        self,
                                        SMBCommand,
                                        packet)
                            else:
                                respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                    connId,
                                    self,
                                    SMBCommand,
                                    packet)
                        else:
                            respCommands, respPackets, errorCode = self.__smbCommands[255](connId, self, SMBCommand,
                                                                                           packet)

                compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                compoundedPackets.append(packet)

            else:
                # Is the client authenticated already?
                if connData['Authenticated'] is False and packet['Command'] not in (
                smb2.SMB2_NEGOTIATE, smb2.SMB2_SESSION_SETUP):
                    # Nope.. in that case he should only ask for a few commands, if not throw him out.
                    errorCode = STATUS_ACCESS_DENIED
                    respPackets = None
                    respCommands = ['']
                    compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                    compoundedPackets.append(packet)
                else:
                    done = False
                    while not done:
                        if packet['Command'] in self.__smb2Commands:
                            if self.__SMB2Support is True:
                                respCommands, respPackets, errorCode = self.__smb2Commands[packet['Command']](
                                    connId,
                                    self,
                                    packet)
                            else:
                                respCommands, respPackets, errorCode = self.__smb2Commands[255](connId, self, packet)
                        else:
                            respCommands, respPackets, errorCode = self.__smb2Commands[255](connId, self, packet)
                        # Let's store the result for this compounded packet
                        compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                        compoundedPackets.append(packet)
                        if packet['NextCommand'] != 0:
                            data = data[packet['NextCommand']:]
                            packet = smb2.SMB2Packet(data=data)
                        else:
                            done = True

        except Exception as e:
            # import traceback
            # traceback.print_exc()
            # Something wen't wrong, defaulting to Bad user ID
            self.log('processRequest (0x%x,%s)' % (packet['Command'], e), logging.ERROR)
            raise

        # We prepare the response packet to commands don't need to bother about that.
        connData = self.getConnectionData(connId, False)

        # Force reconnection loop.. This is just a test.. client will send me back credentials :)
        # connData['PacketNum'] += 1
        # if connData['PacketNum'] == 15:
        #    connData['PacketNum'] = 0
        #    # Something wen't wrong, defaulting to Bad user ID
        #    self.log('Sending BAD USER ID!', logging.ERROR)
        #    #raise
        #    packet['Flags1'] |= smb.SMB.FLAGS1_REPLY
        #    packet['Flags2'] = 0
        #    errorCode = STATUS_SMB_BAD_UID
        #    packet['ErrorCode']   = errorCode >> 16
        #    packet['ErrorClass']  = errorCode & 0xff
        #    return [packet]

        self.setConnectionData(connId, connData)

        packetsToSend = []
        for packetNum in range(len(compoundedPacketsResponse)):
            respCommands, respPackets, errorCode = compoundedPacketsResponse[packetNum]
            packet = compoundedPackets[packetNum]
            if respPackets is None:
                for respCommand in respCommands:
                    if isSMB2 is False:
                        respPacket = smb.NewSMBPacket()
                        respPacket['Flags1'] = smb.SMB.FLAGS1_REPLY

                        # TODO this should come from a per session configuration
                        respPacket[
                            'Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | \
                                        packet['Flags2'] & smb.SMB.FLAGS2_UNICODE
                        # respPacket['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES
                        # respPacket['Flags1'] = 0x98
                        # respPacket['Flags2'] = 0xc807

                        respPacket['Tid'] = packet['Tid']
                        respPacket['Mid'] = packet['Mid']
                        respPacket['Pid'] = packet['Pid']
                        respPacket['Uid'] = connData['Uid']

                        respPacket['ErrorCode'] = errorCode >> 16
                        respPacket['_reserved'] = errorCode >> 8 & 0xff
                        respPacket['ErrorClass'] = errorCode & 0xff
                        respPacket.addCommand(respCommand)

                        if connData['SignatureEnabled']:
                            respPacket['Flags2'] |= smb.SMB.FLAGS2_SMB_SECURITY_SIGNATURE
                            self.signSMBv1(connData, respPacket, connData['SigningSessionKey'],
                                           connData['SigningChallengeResponse'])

                        packetsToSend.append(respPacket)
                    else:
                        respPacket = smb2.SMB2Packet()
                        respPacket['Flags'] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
                        if packetNum > 0:
                            respPacket['Flags'] |= smb2.SMB2_FLAGS_RELATED_OPERATIONS
                        respPacket['Status'] = errorCode
                        respPacket['CreditRequestResponse'] = packet['CreditRequestResponse']
                        respPacket['Command'] = packet['Command']
                        respPacket['CreditCharge'] = packet['CreditCharge']
                        # respPacket['CreditCharge'] = 0
                        respPacket['Reserved'] = packet['Reserved']
                        respPacket['SessionID'] = connData['Uid']
                        respPacket['MessageID'] = packet['MessageID']
                        respPacket['TreeID'] = packet['TreeID']
                        if hasattr(respCommand, 'getData'):
                            respPacket['Data'] = respCommand.getData()
                        else:
                            respPacket['Data'] = str(respCommand)

                        packetsToSend.append(respPacket)
            else:
                # The SMBCommand took care of building the packet
                packetsToSend = respPackets

        if isSMB2 is True:
            # Let's build a compound answer and sign it
            finalData = []
            totalPackets = len(packetsToSend)
            for idx, packet in enumerate(packetsToSend):
                padLen = -len(packet) % 8
                if idx + 1 < totalPackets:
                    packet['NextCommand'] = len(packet) + padLen

                if connData['SignatureEnabled']:
                    self.signSMBv2(packet, connData['SigningSessionKey'], padLength=padLen)

                if hasattr(packet, 'getData'):
                    finalData.append(packet.getData() + padLen * b'\x00')
                else:
                    finalData.append(packet + padLen * b'\x00')

            packetsToSend = [b"".join(finalData)]

        # We clear the compound requests
        connData['LastRequest'] = {}

        return packetsToSend

    def processConfigFile(self, configFile=None):
        # TODO: Do a real config parser
        if self.__serverConfig is None:
            if configFile is None:
                configFile = 'smb.conf'
            self.__serverConfig = configparser.ConfigParser()
            self.__serverConfig.read(configFile)

        self.__serverName = self.__serverConfig.get('global', 'server_name')
        self.__serverOS = self.__serverConfig.get('global', 'server_os')
        self.__serverDomain = self.__serverConfig.get('global', 'server_domain')

        if self.__serverConfig.has_option('global', 'computer_account_name'):
            self.__computerAccountName = self.__serverConfig.get('global', 'computer_account_name')
            self.__computerAccountNTHash = self.__serverConfig.get('global', 'computer_account_hash')
            self.__computerAccountAES = self.__serverConfig.get('global', 'computer_account_aes')
            self.__computerAccountPassword = self.__serverConfig.get('global', 'computer_account_password')
            self.__computerAccountDomain = self.__serverConfig.get('global', 'computer_account_domain')
            self.__domainControllerIP = self.__serverConfig.get('global', 'dcip')

        self.__logFile = self.__serverConfig.get('global', 'log_file')
        if self.__serverConfig.has_option('global', 'challenge'):
            self.__challenge = unhexlify(self.__serverConfig.get('global', 'challenge'))
        else:
            self.__challenge = b'A' * 8

        if self.__serverConfig.has_option("global", "jtr_dump_path"):
            self.__jtr_dump_path = self.__serverConfig.get("global", "jtr_dump_path")

        if self.__serverConfig.has_option("global", "dump_hashes"):
            self.__dump_hashes = self.__serverConfig.getboolean("global", "dump_hashes")
        else:
            self.__dump_hashes = False

        if self.__serverConfig.has_option("global", "SMB2Support"):
            self.__SMB2Support = self.__serverConfig.getboolean("global", "SMB2Support")
        else:
            self.__SMB2Support = False

        if self.__serverConfig.has_option("global", "DropSSP"):
            self.__dropSSP = self.__serverConfig.getboolean("global", "DropSSP")
        else:
            self.__dropSSP = False
        if self.__serverConfig.has_option("global", "KerberosSupport"):
            self.__KerberosSupport = self.__serverConfig.getboolean("global", "KerberosSupport")
        else:
            self.__KerberosSupport = False
        
        if self.__serverConfig.has_option("global", "NTLMSupport"):
            self.__NTLMSupport = self.__serverConfig.getboolean("global", "NTLMSupport")
        else:
            self.__NTLMSupport = True

        if self.__serverConfig.has_option("global", "anonymous_logon"):
            self.__anonymousLogon = self.__serverConfig.getboolean("global", "anonymous_logon")
        else:
            self.__anonymousLogon = True

        if self.__logFile != 'None':
            logging.basicConfig(filename=self.__logFile,
                                level=logging.DEBUG,
                                format="%(asctime)s: %(levelname)s: %(message)s",
                                datefmt='%m/%d/%Y %I:%M:%S %p',
                                force=True)
        self.__log = LOG

        # Process the credentials
        credentials_fname = self.__serverConfig.get('global', 'credentials_file')
        if credentials_fname != "":
            cred = open(credentials_fname)
            line = cred.readline()
            while line:
                name, uid, lmhash, nthash = line.split(':')
                self.__credentials[name.lower()] = (uid, lmhash, nthash.strip('\r\n'))
                line = cred.readline()
            cred.close()
        self.log('Config file parsed')

    def addCredential(self, name, uid, lmhash, nthash):
        # If we have hashes, normalize them
        pass

    def setComputerAccountCredentials(self, username, domain, dcip, nthash="", aes="", password=""):
        pass

    def getComputerAccountCredentials(self):
        pass


# For windows platforms, opening a directory is not an option, so we set a void FD
VOID_FILE_DESCRIPTOR = -1
PIPE_FILE_DESCRIPTOR = -2

######################################################################
# HELPER CLASSES
######################################################################

from impacket.dcerpc.v5.rpcrt import DCERPCServer
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.srvs import NetrShareEnum, NetrShareEnumResponse, SHARE_INFO_1, NetrServerGetInfo, \
    NetrServerGetInfoResponse, NetrShareGetInfo, NetrShareGetInfoResponse
from impacket.dcerpc.v5.wkst import NetrWkstaGetInfo, NetrWkstaGetInfoResponse
from impacket.system_errors import ERROR_INVALID_LEVEL


class WKSTServer(DCERPCServer):
    def __init__(self):
        DCERPCServer.__init__(self)
        self.wkssvcCallBacks = {
            0: self.NetrWkstaGetInfo,
        }
        self.addCallbacks(('6BFFD098-A112-3610-9833-46C3F87E345A', '1.0'), '\\PIPE\\wkssvc', self.wkssvcCallBacks)

    def NetrWkstaGetInfo(self, data):
        request = NetrWkstaGetInfo(data)
        self.log("NetrWkstaGetInfo Level: %d" % request['Level'])

        answer = NetrWkstaGetInfoResponse()

        if request['Level'] not in (100, 101):
            answer['ErrorCode'] = ERROR_INVALID_LEVEL
            return answer

        answer['WkstaInfo']['tag'] = request['Level']

        if request['Level'] == 100:
            # Windows. Decimal value 500.
            answer['WkstaInfo']['WkstaInfo100']['wki100_platform_id'] = 0x000001F4
            answer['WkstaInfo']['WkstaInfo100']['wki100_computername'] = NULL
            answer['WkstaInfo']['WkstaInfo100']['wki100_langroup'] = NULL
            answer['WkstaInfo']['WkstaInfo100']['wki100_ver_major'] = 5
            answer['WkstaInfo']['WkstaInfo100']['wki100_ver_minor'] = 0
        else:
            # Windows. Decimal value 500.
            answer['WkstaInfo']['WkstaInfo101']['wki101_platform_id'] = 0x000001F4
            answer['WkstaInfo']['WkstaInfo101']['wki101_computername'] = NULL
            answer['WkstaInfo']['WkstaInfo101']['wki101_langroup'] = NULL
            answer['WkstaInfo']['WkstaInfo101']['wki101_ver_major'] = 5
            answer['WkstaInfo']['WkstaInfo101']['wki101_ver_minor'] = 0
            answer['WkstaInfo']['WkstaInfo101']['wki101_lanroot'] = NULL

        return answer


class SRVSServer(DCERPCServer):
    def __init__(self):
        DCERPCServer.__init__(self)

        self._shares = {}
        self.__serverConfig = None
        self.__logFile = None

        self.srvsvcCallBacks = {
            15: self.NetrShareEnum,
            16: self.NetrShareGetInfo,
            21: self.NetrServerGetInfo,
        }

        self.addCallbacks(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0'), '\\PIPE\\srvsvc', self.srvsvcCallBacks)

    def setServerConfig(self, config):
        pass

    def processConfigFile(self, configFile=None):
        if configFile is not None:
            self.__serverConfig = configparser.ConfigParser()
            self.__serverConfig.read(configFile)
        sections = self.__serverConfig.sections()
        # Let's check the log file
        self.__logFile = self.__serverConfig.get('global', 'log_file')
        if self.__logFile != 'None':
            logging.basicConfig(filename=self.__logFile,
                                level=logging.DEBUG,
                                format="%(asctime)s: %(levelname)s: %(message)s",
                                datefmt='%m/%d/%Y %I:%M:%S %p')

        # Remove the global one
        del (sections[sections.index('global')])
        self._shares = {}
        for i in sections:
            self._shares[i] = dict(self.__serverConfig.items(i))

    def NetrShareGetInfo(self, data):
        request = NetrShareGetInfo(data)
        self.log("NetrGetShareInfo Level: %d" % request['Level'])

        s = request['NetName'][:-1].upper()
        answer = NetrShareGetInfoResponse()
        if s in self._shares:
            share = self._shares[s]

            answer['InfoStruct']['tag'] = 1
            answer['InfoStruct']['ShareInfo1']['shi1_netname'] = s + '\x00'
            answer['InfoStruct']['ShareInfo1']['shi1_type'] = share['share type']
            answer['InfoStruct']['ShareInfo1']['shi1_remark'] = share['comment'] + '\x00'
            answer['ErrorCode'] = 0
        else:
            answer['InfoStruct']['tag'] = 1
            answer['InfoStruct']['ShareInfo1'] = NULL
            answer['ErrorCode'] = 0x0906  # WERR_NET_NAME_NOT_FOUND

        return answer

    def NetrServerGetInfo(self, data):
        request = NetrServerGetInfo(data)
        self.log("NetrServerGetInfo Level: %d" % request['Level'])
        answer = NetrServerGetInfoResponse()
        answer['InfoStruct']['tag'] = 101
        # PLATFORM_ID_NT = 500
        answer['InfoStruct']['ServerInfo101']['sv101_platform_id'] = 500
        answer['InfoStruct']['ServerInfo101']['sv101_name'] = request['ServerName']
        # Windows 7 = 6.1
        answer['InfoStruct']['ServerInfo101']['sv101_version_major'] = 6
        answer['InfoStruct']['ServerInfo101']['sv101_version_minor'] = 1
        # Workstation = 1
        answer['InfoStruct']['ServerInfo101']['sv101_type'] = 1
        answer['InfoStruct']['ServerInfo101']['sv101_comment'] = NULL
        answer['ErrorCode'] = 0
        return answer

    def NetrShareEnum(self, data):
        request = NetrShareEnum(data)
        self.log("NetrShareEnum Level: %d" % request['InfoStruct']['Level'])
        shareEnum = NetrShareEnumResponse()
        shareEnum['InfoStruct']['Level'] = 1
        shareEnum['InfoStruct']['ShareInfo']['tag'] = 1
        shareEnum['TotalEntries'] = len(self._shares)
        shareEnum['InfoStruct']['ShareInfo']['Level1']['EntriesRead'] = len(self._shares)
        shareEnum['ErrorCode'] = 0

        for i in self._shares:
            shareInfo = SHARE_INFO_1()
            shareInfo['shi1_netname'] = i + '\x00'
            shareInfo['shi1_type'] = self._shares[i]['share type']
            shareInfo['shi1_remark'] = self._shares[i]['comment'] + '\x00'
            shareEnum['InfoStruct']['ShareInfo']['Level1']['Buffer'].append(shareInfo)

        return shareEnum


class SimpleSMBServer:
    """
    SimpleSMBServer class - Implements a simple, customizable SMB Server

    :param string listenAddress: the address you want the server to listen on
    :param integer listenPort: the port number you want the server to listen on
    :param string configFile: a file with all the servers' configuration. If no file specified, this class will create the basic parameters needed to run. You will need to add your shares manually tho. See addShare() method
    """

    def __init__(self, listenAddress='0.0.0.0', listenPort=445, configFile='', smbserverclass=SMBSERVER, ipv6=False):
        if configFile != '':
            self.__server = smbserverclass((listenAddress, listenPort), ipv6=ipv6)
            self.__server.processConfigFile(configFile)
            self.__smbConfig = None
        else:
            # Here we write a mini config for the server
            self.__smbConfig = configparser.ConfigParser()
            self.__smbConfig.add_section('global')
            self.__smbConfig.set('global', 'server_name',
                                 ''.join([random.choice(string.ascii_letters) for _ in range(8)]))
            self.__smbConfig.set('global', 'server_os', ''.join([random.choice(string.ascii_letters) for _ in range(8)])
                                 )
            self.__smbConfig.set('global', 'server_domain',
                                 ''.join([random.choice(string.ascii_letters) for _ in range(8)])
                                 )
            self.__smbConfig.set('global', 'log_file', 'None')
            self.__smbConfig.set('global', 'rpc_apis', 'yes')
            self.__smbConfig.set('global', 'credentials_file', '')
            self.__smbConfig.set('global', 'challenge', "A" * 16)

            # IPC always needed
            self.__smbConfig.add_section('IPC$')
            self.__smbConfig.set('IPC$', 'comment', '')
            self.__smbConfig.set('IPC$', 'read only', 'yes')
            self.__smbConfig.set('IPC$', 'share type', '3')
            self.__smbConfig.set('IPC$', 'path', '')
            self.__server = smbserverclass((listenAddress, listenPort), config_parser=self.__smbConfig, ipv6=ipv6)
            self.__server.processConfigFile()

        # Now we have to register the MS-SRVS server. This specially important for
        # Windows 7+ and Mavericks clients since they WON'T (specially OSX)
        # ask for shares using MS-RAP.

        self.__srvsServer = SRVSServer()
        self.__srvsServer.daemon=True
        self.__wkstServer = WKSTServer()
        self.__wkstServer.daemon=True
        self.__server.registerNamedPipe('srvsvc', ('127.0.0.1', self.__srvsServer.getListenPort()))
        self.__server.registerNamedPipe('wkssvc', ('127.0.0.1', self.__wkstServer.getListenPort()))

    def getServer(self):
        pass

    def start(self):
        self.__srvsServer.start()
        self.__wkstServer.start()
        self.__server.serve_forever()

    def stop(self):
        self.__server.server_close()

    def registerNamedPipe(self, pipeName, address):
        return self.__server.registerNamedPipe(pipeName, address)

    def unregisterNamedPipe(self, pipeName):
        pass

    def getRegisteredNamedPipes(self):
        pass

    def addShare(self, shareName, sharePath, shareComment='', shareType='0', readOnly='no'):
        pass

    def removeShare(self, shareName):
        pass

    def setSMBChallenge(self, challenge):
        pass

    def setLogFile(self, logFile):
        pass

    def setCredentialsFile(self, logFile):
        pass

    def addCredential(self, name, uid, lmhash, nthash):
        pass

    def setComputerAccount(self, computer_account_name, computer_account_hash, computer_account_aes, computer_account_password, computer_account_domain, dcip):
        # needs to be correct for netlogon to allow us to authenticate the user
        pass


    def setSMB2Support(self, value):
        pass

    def setNTLMSupport(self, value):
        pass

    def setKerberosSupport(self, value):
        pass

    def getAuthCallback(self):
        pass

    def setAuthCallback(self, callback):
        self.__server.setAuthCallback(callback)

    def setDropSSP(self, value):
        pass

# https://gist.github.com/ThePirateWhoSmellsOfSunflowers/f41c334f912ec033d9bbfc7e96308ec6
class NetLogon:
    nrpc_uid = nrpc.MSRPC_UUID_NRPC
    syntax = rpcrt.DCERPC.NDRSyntax
    authn_level_packet = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY # KB5021130

    def __init__(self, dcip, computer_account_name, computer_account_hash, computer_account_domain, client_challenge=random.randbytes(8), computer_name=None, primary_name=""):
        self.dcip = dcip
        self.computer_account_name = computer_account_name
        if computer_name is not None:
            self.computer_name = computer_name
        else:
            self.computer_name = computer_account_name[:-1] # strip $
        self.computer_account_hash = unhexlify(computer_account_hash)
        self.computer_account_domain = computer_account_domain
        self.client_challenge = client_challenge
        self.primary_name = primary_name
        self.authenticator = None
        self.dce = None

    def setupConnection(self):
        pass

    def logonUserAndGetSessionKey(self, authenticateMessage, serverChallenge):
        pass
