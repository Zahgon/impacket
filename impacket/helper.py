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
#   Helper used to build ProtocolPackets
#
# Author:
#   Aureliano Calvo
#

import struct
import functools
from six import add_metaclass

import impacket.ImpactPacket as ip


def rebind(f):
    pass

class Field(object):
    def __init__(self, index):
        self.index = index
    
    def __call__(self, k, d):
        getter = rebind(self.getter)
        getter_name = "get_" + k
        getter.__name__ = getter_name
        getter.__doc__ = "Get the %s field" % k
        d[getter_name] = getter
        
        setter = rebind(self.setter)
        setter_name = "set_" + k
        setter.__name__ = setter_name
        setter.__doc__ = "Set the %s field" % k
        d["set_" + k] = setter
        
        d[k] = property(getter, setter, doc="%s property" % k)
        
class Bit(Field):
    def __init__(self, index, bit_number):
        Field.__init__(self, index)
        self.mask = 2 ** bit_number
        self.off_mask = (~self.mask) & 0xff
        
    def getter(self, o):
        pass
    
    def setter(self, o, value=True):
        pass

class Byte(Field):
    
    def __init__(self, index):
        Field.__init__(self, index)
        
    def getter(self, o):
        pass
    
    def setter(self, o, value):
        pass
        
class Word(Field):
    def __init__(self, index, order="!"):
        Field.__init__(self, index)
        self.order = order
        
    def getter(self, o):
        pass
    
    def setter(self, o, value):
        pass

class Long(Field):        
    def __init__(self, index, order="!"):
        Field.__init__(self, index)        
        self.order = order
        
    def getter(self, o):
        pass
    
    def setter(self, o, value):
        pass
        
class ThreeBytesBigEndian(Field):
    def __init__(self, index):
        Field.__init__(self, index)
                
    def getter(self, o):
        pass

    def setter(self, o, value):
        # clear the bits
        pass


class ProtocolPacketMetaklass(type):
    def __new__(cls, name, bases, d):
        d["_fields"] = []
        items = list(d.items())
        if not object in bases:
            bases += (object,)
        for k,v in items:
            if isinstance(v, Field):
                d["_fields"].append(k) 
                v(k, d)
                
        d["_fields"].sort()
        
        def _fields_repr(self):
            return " ".join( "%s:%s" % (f, repr(getattr(self, f))) for f in self._fields )
        def __repr__(self):
            
            return "<%(name)s %(fields)s \nchild:%(r_child)s>" % {
                "name": name,
                "fields": self._fields_repr(),
                "r_child": repr(self.child()), 
            }
        
        d["_fields_repr"] = _fields_repr
        d["__repr__"] = __repr__
        
        return type.__new__(cls, name, bases, d)

@add_metaclass(ProtocolPacketMetaklass)
class ProtocolPacket(ip.ProtocolPacket):
    def __init__(self, buff = None):
        ip.ProtocolPacket.__init__(self, self.header_size, self.tail_size)
        if buff:
            self.load_packet(buff)
