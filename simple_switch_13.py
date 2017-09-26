#Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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
import struct
from ryu.lib import ip
import httplib

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.src_list={}

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,0)


############Working version commented#################
    #def add_flow(self, datapath, priority, match, actions,cookie, buffer_id=None):
    #    ofproto = datapath.ofproto
    #    parser = datapath.ofproto_parser

   #     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
    #                                         actions)]
    #    if buffer_id:
    #        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
    #                                priority=priority, match=match,
    #                                instructions=inst,cookie=cookie)
    #    else:
    #        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
    #                                match=match, instructions=inst,cookie=cookie)
    #    datapath.send_msg(mod)

###################New code added:16th August 2016######################
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
        datapath.send_msg(mod)

# Packet handler. Executes commands when a packet arrives at the controller

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
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
# MAC addresses:

        dst = eth.dst
        src = eth.src
        type = eth.ethertype

# Protocol declarations:

        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
	pkt_ipv4= pkt.get_protocol(ipv4.ipv4)

        if pkt_arp:
            src1 = pkt_arp.src_ip
            dst1 = pkt_arp.dst_ip
        elif pkt_ipv4:
            src1=pkt_ipv4.src 
            dst1=pkt_ipv4.dst
        dpid = datapath.id

# Port identification, depending on the incoming MAC address

        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port=ofproto.OFPP_FLOOD

# Recording of all the source & destination IP for each DPID with format: srcIP|dstIP

        if not dpid in self.src_list:
                self.src_list[dpid]=[]

# A flow is added only when the set srcIP|dstIP has not been processed. Not required, but allows better understanding of the flows
# When the packets destination (i.e out_port) is known, and the DPID is the one of S5, we add the flow and request the cookie from C0


        if (not (src1+'|'+dst1 in self.src_list[dpid] and out_port==ofproto.OFPP_FLOOD) and dpid==5):
	     match = parser.OFPMatch(in_port=in_port, eth_type=0x800,ipv4_src=src1, ipv4_dst=dst1)
             actions = [parser.OFPActionOutput(3-in_port)]
             #if (ip_dscp==34):
             #    actions = [parser.OFPActionOutput(3)]
             #else:
             #    actions = [parser.OFPActionOutput(3-in_port)]
            
             cookie=0
             conn = httplib.HTTPConnection("127.0.0.1", 8080) # Please hide IP
             if in_port==2: # For packets arriving from S4, we add the cookie to our flow in order to count the packets on the monitor
                 url="/simpleswitch/gettag/"+src1
                 conn.request("GET", url)
                 response=conn.getresponse()
                 if response.status==200: # We make sure that we get a HTTP_SUCCESS response
                 	cookie=int(response.read())
                 	print "Got cookie from C0: ",cookie

# For packets arriving from other sources, we don't need to count the packets, so we leave the cookie to 0
# The flow is added and the cookie field is set. Here we don't modify the flow, so we don't match a specific cookie/cookie_mask

                        self.add_flow(datapath, 1, match, actions,cookie=cookie)
                        self.src_list[dpid].append(src1+'|'+dst1) # We make sure to learn the set srcIP|dstIP for the next time
                        print "Installing flow\n#########################################################"
        #if (dpid == 13):
        #    match = parser.OFPMatch(in_port=in_port, eth_type=0x800,ipv4_src=src1, ipv4_dst=dst1)
        #    actions = [parser.OFPActionOutput(3-in_port)]
        #    cookie=0
        #    self.add_flow(datapath, 1, match, actions,cookie=cookie)
        #if (dpid == 5 and in_port == 1 and dst1 =='10.0.0.2'):
        #    match = parser.OFPMatch(in_port=in_port, eth_type=0x800,ipv4_src=src1, ipv4_dst=dst1)
        #    actions = [parser.OFPActionOutput(2)]
        #    cookie=0
        #    self.add_flow(datapath, 1, match, actions,cookie=cookie)
        else: # If the conditions are not met, then the packet is flooding, so we just pass it along
             actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        ####Working version #######
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        #out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  #in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
