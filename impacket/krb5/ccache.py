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
#   Kerberos Credential Cache format implementation
#   based on file format described at:
#   https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt
#   Pretty lame and quick implementation, not a fun thing to do
#   Contribution is welcome to make it the right way
#
# Author:
#   Alberto Solino (@agsolino)
#
from __future__ import division
from __future__ import print_function
from datetime import datetime, timezone
import os
from struct import pack, unpack, calcsize
from six import b, PY2

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from binascii import hexlify

from impacket.structure import Structure
from impacket.krb5 import crypto, constants, types
from impacket.krb5.asn1 import AS_REP, seq_set, TGS_REP, EncTGSRepPart, EncASRepPart, Ticket, KRB_CRED, \
    EncKrbCredPart, KrbCredInfo, seq_set_iter
from impacket.krb5.types import KerberosTime
from impacket import LOG

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

DELTA_TIME = 1

class Header(Structure):
    structure = (
        ('tag','!H=0'),
        ('taglen','!H=0'),
        ('_tagdata','_-tagdata','self["taglen"]'),
        ('tagdata',':'),
    )

class DeltaTime(Structure):
    structure = (
        ('time_offset','!L=0'),
        ('usec_offset','!L=0'),
    )

class CountedOctetString(Structure):
    structure = (
        ('length','!L=0'),
        ('_data','_-data','self["length"]'),
        ('data',':'),
    )

    def prettyPrint(self, indent=''):
        return "%s%s" % (indent, hexlify(self['data']))


class KeyBlockV3(Structure):
    structure = (
        ('keytype','!H=0'),
        ('etype','!H=0'),
        ('etype2', '!H=0'),  # Version 3 repeats the etype
        ('keylen','!H=0'),
        ('_keyvalue','_-keyvalue','self["keylen"]'),
        ('keyvalue',':'),
    )

    def prettyPrint(self):
        return "Key: (0x%x)%s" % (self['keytype'], hexlify(self['keyvalue']))


class KeyBlockV4(Structure):
    structure = (
        ('keytype','!H=0'),
        ('etype','!H=0'),
        ('keylen','!H=0'),
        ('_keyvalue','_-keyvalue','self["keylen"]'),
        ('keyvalue',':'),
    )

    def prettyPrint(self):
        return "Key: (0x%x)%s" % (self['keytype'], hexlify(self['keyvalue']))

class Times(Structure):
    structure = (
        ('authtime','!L=0'),
        ('starttime','!L=0'),
        ('endtime','!L=0'),
        ('renew_till','!L=0'),
    )
    def prettyPrint(self, indent = ''):
        print(("%sAuth : %s" % (indent, datetime.fromtimestamp(self['authtime']).isoformat())))
        print(("%sStart: %s" % (indent, datetime.fromtimestamp(self['starttime']).isoformat())))
        print(("%sEnd  : %s" % (indent, datetime.fromtimestamp(self['endtime']).isoformat())))
        print(("%sRenew: %s" % (indent, datetime.fromtimestamp(self['renew_till']).isoformat())))

class Address(Structure):
    structure = (
        ('addrtype','!H=0'),
        ('addrdata',':', CountedOctetString),
    )

class AuthData(Structure):
    structure = (
        ('authtype','!H=0'),
        ('authdata',':', CountedOctetString),
    )

class Principal:
    class PrincipalHeader(Structure):
        structure = (
            ('name_type','!L=0'),
            ('num_components','!L=0'),
        )
    def __init__(self, data=None):
        self.components = []
        self.realm = None
        if data is not None:
            self.header = self.PrincipalHeader(data)
            data = data[len(self.header):]
            self.realm = CountedOctetString(data)
            data = data[len(self.realm):]
            self.components = []
            for component in range(self.header['num_components']):
                comp = CountedOctetString(data)
                data = data[len(comp):]
                self.components.append(comp)
        else:
            self.header = self.PrincipalHeader()

    def __len__(self):
        totalLen = len(self.header) + len(self.realm)
        for i in self.components:
            totalLen += len(i)
        return totalLen

    def getData(self):
        data = self.header.getData() + self.realm.getData()
        for component in self.components:
            data += component.getData()
        return data

    def __str__(self):
        return self.getData()

    def prettyPrint(self):
        principal = b''
        for component in self.components:
            if isinstance(component['data'], bytes) is not True:
                component = b(component['data'])
            else:
                component = component['data']
            principal += component + b'/'

        principal = principal[:-1]
        if isinstance(self.realm['data'], bytes):
            realm = self.realm['data']
        else:
            realm = b(self.realm['data'])
        principal += b'@' + realm
        return principal

    def fromPrincipal(self, principal):
        pass

    def toPrincipal(self):
        return types.Principal(self.prettyPrint(), type=self.header['name_type'])

class Credential:
    class CredentialHeaderV3(Structure):
        structure = (
            ('client',':', Principal),
            ('server',':', Principal),
            ('key',':', KeyBlockV3),
            ('time',':', Times),
            ('is_skey','B=0'),
            ('tktflags','!L=0'),
            ('num_address','!L=0'),
        )

    class CredentialHeaderV4(Structure):
        structure = (
            ('client',':', Principal),
            ('server',':', Principal),
            ('key',':', KeyBlockV4),
            ('time',':', Times),
            ('is_skey','B=0'),
            ('tktflags','!L=0'),
            ('num_address','!L=0'),
        )

    def __init__(self, data=None, ccache_version=None):
        self.addresses = ()
        self.authData = ()
        self.header = None
        self.ticket = None
        self.secondTicket = None

        if data is not None:
            if ccache_version == 3:
                self.header = self.CredentialHeaderV3(data)
            else:
                self.header = self.CredentialHeaderV4(data)

            data = data[len(self.header):]
            self.addresses = []
            for address in range(self.header['num_address']):
                ad = Address(data)
                data = data[len(ad):]
                self.addresses.append(ad)
            num_authdata = unpack('!L', data[:4])[0]
            data = data[calcsize('!L'):]
            for authdata in range(num_authdata):
                ad = AuthData(data)
                data = data[len(ad):]
                self.authData.append(ad)
            self.ticket = CountedOctetString(data)
            data = data[len(self.ticket):]
            self.secondTicket = CountedOctetString(data)
            data = data[len( self.secondTicket):]
        else:
            self.header = self.CredentialHeaderV4()

    def __getitem__(self, key):
        return self.header[key]

    def __setitem__(self, item, value):
        self.header[item] = value

    def getServerPrincipal(self):
        pass

    def __len__(self):
        totalLen = len(self.header)
        for i in self.addresses:
            totalLen += len(i)
        totalLen += calcsize('!L')
        for i in self.authData:
            totalLen += len(i)
        totalLen += len(self.ticket)
        totalLen += len(self.secondTicket)
        return totalLen

    def dump(self):
        self.header.dump()

    def getData(self):
        data = self.header.getData()
        for i in self.addresses:
            data += i.getData()
        data += pack('!L', len(self.authData))
        for i in self.authData:
            data += i.getData()
        data += self.ticket.getData()
        data += self.secondTicket.getData()
        return data

    def __str__(self):
        return self.getData()

    def prettyPrint(self, indent=''):
        print(("%sClient: %s" % (indent, self.header['client'].prettyPrint())))
        print(("%sServer: %s" % (indent, self.header['server'].prettyPrint())))
        print(("%s%s" % (indent, self.header['key'].prettyPrint())))
        print(("%sTimes: " % indent))
        self.header['time'].prettyPrint('\t\t')
        print(("%sSubKey: %s" % (indent, self.header['is_skey'])))
        print(("%sFlags: 0x%x" % (indent, self.header['tktflags'])))
        print(("%sAddresses: %d" % (indent, self.header['num_address'])))
        for address in self.addresses:
            address.prettyPrint('\t\t')
        print(("%sAuth Data: %d" % (indent, len(self.authData))))
        for ad in self.authData:
            ad.prettyPrint('\t\t')
        print(("%sTicket: %s" % (indent, self.ticket.prettyPrint())))
        print(("%sSecond Ticket: %s" % (indent, self.secondTicket.prettyPrint())))

    def toTGT(self):
        tgt_rep = AS_REP()
        tgt_rep['pvno'] = 5
        tgt_rep['msg-type'] = int(constants.ApplicationTagNumbers.AS_REP.value)
        tgt_rep['crealm'] = self['server'].realm['data']

        # Fake EncryptedData
        tgt_rep['enc-part'] = noValue
        tgt_rep['enc-part']['etype'] = 1
        tgt_rep['enc-part']['cipher'] = ''
        seq_set(tgt_rep, 'cname', self['client'].toPrincipal().components_to_asn1)
        ticket = types.Ticket()
        ticket.from_asn1(self.ticket['data'])
        seq_set(tgt_rep,'ticket', ticket.to_asn1)

        cipher = crypto._enctype_table[self['key']['keytype']]()

        tgt = dict()
        tgt['KDC_REP'] = encoder.encode(tgt_rep)
        tgt['cipher'] = cipher
        tgt['sessionKey'] = crypto.Key(cipher.enctype, self['key']['keyvalue'])
        return tgt

    def toTGS(self, newSPN=None):
        tgs_rep = TGS_REP()
        tgs_rep['pvno'] = 5
        tgs_rep['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REP.value)
        tgs_rep['crealm'] = self['server'].realm['data']

        # Fake EncryptedData
        tgs_rep['enc-part'] = noValue
        tgs_rep['enc-part']['etype'] = 1
        tgs_rep['enc-part']['cipher'] = ''
        seq_set(tgs_rep, 'cname', self['client'].toPrincipal().components_to_asn1)
        ticket = types.Ticket()
        ticket.from_asn1(self.ticket['data'])
        if newSPN is not None:
            if newSPN.upper() != str(ticket.service_principal).upper():
                LOG.debug('Changing sname from %s to %s and hoping for the best' % (ticket.service_principal, newSPN) )
                ticket.service_principal = types.Principal(newSPN, type=int(ticket.service_principal.type))
        seq_set(tgs_rep,'ticket', ticket.to_asn1)

        cipher = crypto._enctype_table[self['key']['keytype']]()

        tgs = dict()
        tgs['KDC_REP'] = encoder.encode(tgs_rep)
        tgs['cipher'] = cipher
        tgs['sessionKey'] = crypto.Key(cipher.enctype, self['key']['keyvalue'])
        return tgs


class CCache:
    # https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html

    class MiniHeader(Structure):
        structure = (
            ('file_format_version','!H=0x0504'),
            ('headerlen','!H=12'),
        )

    def __init__(self, data = None):
        self.headers = None
        self.principal = None
        self.credentials = []
        self.miniHeader = None

        if data is not None:
            if PY2:
                ccache_version = unpack('>B', data[1])[0]
            else:
                ccache_version = data[1]

            # Versions 1 and 2 are not implemented yet
            if ccache_version == 1 or ccache_version == 2:
                raise NotImplementedError('Not Implemented!')

            # Only Version 4 contains a header
            if ccache_version == 4:
                miniHeader = self.MiniHeader(data)
                data = data[len(miniHeader.getData()):]

                headerLen = miniHeader['headerlen']

                self.headers = []
                while headerLen > 0:
                    header = Header(data)
                    self.headers.append(header)
                    headerLen -= len(header)
                    data = data[len(header):]
            else:
                # Skip over the version bytes
                data = data[2:]

            # Now the primary_principal
            self.principal = Principal(data)

            data = data[len(self.principal):]

            # Now let's parse the credentials
            self.credentials = []
            while len(data) > 0:
                cred = Credential(data, ccache_version)
                if cred['server'].prettyPrint().find(b'krb5_ccache_conf_data') < 0:
                    self.credentials.append(cred)
                data = data[len(cred.getData()):]

    def getData(self):
        data = self.MiniHeader().getData()
        for header in self.headers:
            data += header.getData()
        data += self.principal.getData()
        for credential in self.credentials:
            data += credential.getData()
        return data

    def getCredential(self, server, anySPN=True):
        for c in self.credentials:
            if c['server'].prettyPrint().upper() == b(server.upper()) or c['server'].prettyPrint().upper().split(b'@')[0] == b(server.upper())\
                    or c['server'].prettyPrint().upper().split(b'@')[0] == b(server.upper().split('@')[0]):
                LOG.debug('Returning cached credential for %s' % c['server'].prettyPrint().upper().decode('utf-8'))
                return c
        LOG.debug('SPN %s not found in cache' % server.upper())
        if anySPN is True:
            LOG.debug('AnySPN is True, looking for another suitable SPN')
            for c in self.credentials:
                # Let's search for any TGT/TGS that matches the server w/o the SPN's service type/port, returns
                # the first one
                # If server has no '/' we assume it's a ST from S4U2Self without a service type
                if c['server'].prettyPrint().find(b'/') >=0:
                    # Let's take the port out for comparison
                    cachedSPN = (c['server'].prettyPrint().upper().split(b'/')[1].split(b'@')[0].split(b':')[0] + b'@' + c['server'].prettyPrint().upper().split(b'/')[1].split(b'@')[1])
                    searchSPN = '%s@%s' % (server.upper().split('/')[1].split('@')[0].split(':')[0],
                                               server.upper().split('/')[1].split('@')[1])
                    if cachedSPN == b(searchSPN):
                        LOG.debug('Returning cached credential for %s' % c['server'].prettyPrint().upper().decode('utf-8'))
                        return c
                else:
                    # Should be of form 'hostname$@REALM'
                    cachedSPN = (c['server'].prettyPrint().upper().split(b'@')[0].split(b':')[0] + b'@' + c['server'].prettyPrint().upper().split(b'@')[1])
                    searchSPN = f"{server.upper().split('/')[1].split('@')[0].split(':')[0].split('.')[0]}$@{server.upper().split('/')[1].split('@')[1]}"
                    if cachedSPN == b(searchSPN):
                        LOG.debug('Returning cached credential for %s' % c['server'].prettyPrint().upper().decode('utf-8'))
                        return c

        return None

    def toTimeStamp(self, dt, epoch=datetime(1970,1,1)):
        pass

    def reverseFlags(self, flags):
        pass

    def fromTGT(self, tgt, oldSessionKey, sessionKey):
        pass

    def fromTGS(self, tgs, oldSessionKey, sessionKey):
        pass

    @classmethod
    def loadFile(cls, fileName):
        if fileName is None:
            LOG.critical('CCache file is not found. Skipping...')
            LOG.debug('The specified path is not correct or the KRB5CCNAME environment variable is not defined')
            return None

        try:
            f = open(fileName, 'rb')
            data = f.read()
            f.close()
            return cls(data)
        except FileNotFoundError as e:
            raise e

    def saveFile(self, fileName):
        pass

    @classmethod
    def parseFile(cls, domain='', username='', target=''):
        """
        parses the CCache file specified in the KRB5CCNAME environment variable

        :param domain: an optional domain name of a user
        :param username: an optional username of a user
        :param target: an optional SPN of a target system

        :return: domain, username, TGT, TGS
        """

        ccache = cls.loadFile(os.getenv('KRB5CCNAME'))
        if ccache is None:
            return domain, username, None, None

        LOG.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))

        if domain == '':
            domain = ccache.principal.realm['data'].decode('utf-8')
            LOG.debug('Domain retrieved from CCache: %s' % domain)

        creds = None
        if target != '':
            principal = '%s@%s' % (target.upper(), domain.upper())
            creds = ccache.getCredential(principal)

        TGT = None
        TGS = None
        if creds is None:
            principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
            creds = ccache.getCredential(principal)
            if creds is not None:
                LOG.debug('Using TGT from cache')
                TGT = creds.toTGT()
            else:
                LOG.debug('No valid credentials found in cache')
        else:
            LOG.debug('Using TGS from cache')
            TGS = creds.toTGS(principal)

        if username == '' and creds is not None:
            username = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
            LOG.debug('Username retrieved from CCache: %s' % username)
        elif username == '' and len(ccache.principal.components) > 0:
            username = ccache.principal.components[0]['data'].decode('utf-8')
            LOG.debug('Username retrieved from CCache: %s' % username)

        return domain, username, TGT, TGS

    def prettyPrint(self):
        print(("Primary Principal: %s" % self.principal.prettyPrint()))
        print("Credentials: ")
        for i, credential in enumerate(self.credentials):
            print(("[%d]" % i))
            credential.prettyPrint('\t')

    @classmethod
    def loadKirbiFile(cls, fileName):
        pass

    def saveKirbiFile(self, fileName):
        pass

    def fromKRBCRED(self, encodedKrbCred):

        pass

    def toKRBCRED(self):
        pass

    def setDefaultHeader(self):
        pass



if __name__ == '__main__':
    ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
    ccache.prettyPrint()
