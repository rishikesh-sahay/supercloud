# Copyright (C) 2010 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import *
from ryu.ofproto.ether import ETH_TYPE_8021Q
from ryu.topology import switches as S_
from ryu.app import *
from ryu.controller.ofp_event import EventOFPSwitchFeatures
from ryu.controller.ofp_event import EventOFPPacketIn
from ryu.lib import ip


import array
import hashlib
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import httplib
from ryu.lib import dpid as dpid_lib
from webob import Response
import json
import logging
import time
import struct
import json
import urlparse
import urllib
from lxml import etree
import xml.etree.ElementTree as ET


import sys

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/changevlan/{dpid}' #

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi': WSGIApplication }
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController, {simple_switch_instance_name : self})
        self.switches = {}
        self.mac_to_port = {} 
        self.datapath = ""
        self.src_ip = ""
        self.dst_ip = ""
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg=ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.parser=parser
        self.switches[datapath.id] = datapath
        self.init_done = 0

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,0)


# Function to add a new flow

    def add_flow(self, datapath, priority, match, actions,cookie, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,cookie=cookie)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,cookie=cookie)
            #print mod
        datapath.send_msg(mod)

# Function to modify an existing flow, based on a cookie/cookie_mask combination

    def modify_flow(self, datapath, priority, match, actions,cookie, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,cookie=cookie,cookie_mask=cookie,command=ofproto.OFPFC_MODIFY, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
    
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie,cookie_mask=cookie,command=ofproto.OFPFC_MODIFY,priority=priority,
                                    match=match, instructions=inst)
    
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # in_port = msg.match['in_port'] working version
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

# Store the vlan_id in order to match it later in the PopVlan

        if pkt.get_protocol(vlan.vlan):
	     vlan_id = pkt.get_protocol(vlan.vlan)
        else:
             vlan_id = None
        #vlan_id = pkt.get_protocol(vlan.vlan)

# MAC addresses:

        dst = eth.dst
        src = eth.src
        type = eth.ethertype

# Protocol declarations:

        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        dst1=""
        if pkt_arp:
            src1 = pkt_arp.src_ip
            self.src_ip = src1   
            dst1 = pkt_arp.dst_ip
            self.dst_ip = dst1
        elif pkt_icmp:
            src1 = pkt_ipv4.src
            self.src_ip = src1
            dst1 = pkt_ipv4.dst
            self.dst_ip = dst1
        elif pkt_ipv4:
            src1=pkt_ipv4.src
            self.src_ip = src1
            dst1=pkt_ipv4.dst
            self.dst_ip = dst1
            tos1=pkt_ipv4.tos
            self.tos_ip = tos1
            ip_proto = pkt_ipv4.proto

        dpid = datapath.id

# Port identification, depending on the incoming MAC address

        self.mac_to_port.setdefault(dpid, {})        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port 

	if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst] 
        else:
            out_port=ofproto.OFPP_FLOOD
        
            
        else: # If the conditions are not met, then the packet is flooding, so we just pass it along
            actions=[parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

# Class to create a server which responds to REST requests

class SimpleSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simpl_switch_spp = data[simple_switch_instance_name]

# Triggered when a mitigation request arrives from C1. We get the cookie and change the VLAN of the corresponding flow

    @route('simpleswitch', url, methods=['PUT'],requirements={'dpid': dpid_lib.DPID_PATTERN})
    def change_rule(self, req, **kwargs): 
        simple_switch = self.simpl_switch_spp
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        content = req.body
        xml_file = ET.ElementTree(ET.fromstring(content))
        my_parser = etree.XMLParser(remove_blank_text = True)
        ID = []
        cookies = xml_file.find('.//Cookie')
        if cookies is not None:
            for cookie in cookies:
                my_id = cookie.attrib['id']
                ID.append(my_id)
        cookie_tag = int(ID[0])

        xpath_IP_source = "descendant::Source/descendant::address"
        source['IP'] = root_node.xpath(xpath_IP_source)[0].text

        xpath_IP_target = "descendant::Target/descendant::address"
        target['IP'] = root_node.xpath(xpath_IP_target)[0].text
        
        security = xml_file.find('.//security')
        my_class = security.attrib['class']
        impact = xml_file.find('.//Impact')
        my_impact = impact.attrib['severity']  ## Get the impact severity from security alert
        customer = xml_file.find('.//Customer')
        my_customer = customer.attrib['network']
        act = xml_file.find('.//Action')
        my_act = act.attrib['request']  ## Get the action requested from the security alert

        event = xml_file.find('.//event')
        my_event = security.attrib['type']  ## Get the type of event from the security alert
            
        if(my_event == 'icmp-flood' my_class == 'suspicious' and my_impact == 'high'):
            xml_file1 = etree.parse("security.xml")
            action = xml_file1.find('.//action')
            my_action = action.attrib['action']

        params = urllib.urlencode({'Source' : source, 'Target' : target, 'Action' : my_action})
        
        conn = httplib.HTTPConnection("127.0.0.1", 8080)
        conn.request("PUT", "/URL/action/", params)     ## Sends the high-level action and cookie details to specified URL

        return Response (status = 200)
    
