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

import array
import struct

from impacket import ImpactPacket
from impacket.ICMP6 import ICMP6


class NDP(ICMP6):
    #ICMP message type numbers
    ROUTER_SOLICITATION = 133
    ROUTER_ADVERTISEMENT = 134
    NEIGHBOR_SOLICITATION = 135
    NEIGHBOR_ADVERTISEMENT = 136
    REDIRECT = 137

############################################################################
# Append NDP Option helper

    def append_ndp_option(self, ndp_option):
        #As NDP inherits ICMP6, it is, in fact an ICMP6 "header"
        #The payload (where all NDP options should reside) is a child of the header
        pass
                
        
############################################################################
    @classmethod
    def Router_Solicitation(class_object):
        pass

    @classmethod
    def Router_Advertisement(class_object, current_hop_limit, 
                             managed_flag, other_flag, 
                             router_lifetime, reachable_time, retransmission_timer):        
        pass

    @classmethod
    def Neighbor_Solicitation(class_object, target_address):        
        pass


    @classmethod
    def Neighbor_Advertisement(class_object, router_flag, solicited_flag, override_flag, target_address):                
        pass


    @classmethod
    def Redirect(class_object, target_address, destination_address):        
        pass

    
    @classmethod
    def __build_message(class_object, type, message_data):
        #Build NDP header
        pass


    
        
class NDP_Option():
    #NDP Option Type numbers
    SOURCE_LINK_LAYER_ADDRESS = 1
    TARGET_LINK_LAYER_ADDRESS = 2
    PREFIX_INFORMATION = 3
    REDIRECTED_HEADER = 4
    MTU_OPTION = 5
    
############################################################################
    @classmethod    
    #link_layer_address must have a size that is a multiple of 8 octets
    def Source_Link_Layer_Address(class_object, link_layer_address):
        pass

    @classmethod    
    #link_layer_address must have a size that is a multiple of 8 octets
    def Target_Link_Layer_Address(class_object, link_layer_address):
        pass

    @classmethod    
    #link_layer_address must have a size that is a multiple of 8 octets
    def __Link_Layer_Address(class_object, option_type, link_layer_address):
        pass

    @classmethod
    #Note: if we upgraded to Python 2.6, we could use collections.namedtuples for encapsulating the arguments
    #ENHANCEMENT - Prefix could be an instance of IP6_Address 
    def Prefix_Information(class_object, prefix_length, on_link_flag, autonomous_flag, valid_lifetime, preferred_lifetime, prefix):
        
        pass
        
        
    @classmethod    
    def Redirected_Header(class_object, original_packet):
        pass
    
    @classmethod    
    def MTU(class_object, mtu):
        pass


    @classmethod
    def __build_option(class_object, type, length, option_data):
        #Pack data
        pass
