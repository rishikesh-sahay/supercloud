from operator import attrgetter

from ryu.app import simple_switch_13

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import struct
from ryu.lib import ip
import time
import httplib
import urllib
#from lxml import etree
#import xml.etree.ElementTree as etree
import lxml.etree as etree
import sys
from ryu.lib.packet import packet

class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    
     #_CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.cond = 0
        self.monitor_thread = hub.spawn(self._monitor)
        self.threshold=50
        #self.threshold=20
	self.src=None
        #self.p0 = 0
        #self.p1 = 0
        # using the register
        #wsgi = kwargs['wsgi']
        #wsgi.register(SimpleSwitchController, {simple_switch_instance_name : self})

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                #print "\n Datapath = ", datapath.id
            elif ev.state == DEAD_DISPATCHER:
                if datapath.id in self.datapaths:
                    self.logger.debug('unregister datapath: %016x', datapath.id)
                    del self.datapaths[datapath.id]

    def _monitor(self):
        self.logger.debug('monitor started')
        while True:
            for dp in self.datapaths.values():
                #print "\n datapath = ", self.datapaths.values(dp)
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016d', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        req = parser.OFPFlowStatsRequest(datapath)
        if ((dpid == 5)):
            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        msg = ev.msg
        body = msg.body
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #p0 = 0
        #pkt = packet.Packet(msg.data)
        #p1 = 0
        #pkt.get_protocol(vlan.vlan):
	#     vlan_id = simple_switch_13.pkt.get_protocol(vlan.vlan)
        #else:
        #     vlan_id = None

#Packets are counted and displayed, based on their IP source and destination, and their Cookie

        self.logger.info('datapath'
                          'in-port '
                          'out-port packets bytes srcIP dstIP cookie')
        self.logger.info('---------------- '
            '-------- ----------------- '
            '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (flow.match['in_port'], flow.match['ipv4_src'], flow.match['ipv4_dst'],flow.cookie)):
            self.logger.info('%016x %8x %8x %8d %8d %17s %17s %17s',
                               ev.msg.datapath.id,
                               stat.match['in_port'],
                               stat.instructions[0].actions[-1].port,
                               stat.packet_count, stat.byte_count, stat.match['ipv4_src'], stat.match['ipv4_dst'],stat.cookie)
            pkt_count = stat.packet_count    #old working version
            self.pkt_count = pkt_count      #old version working
            in_port = stat.match['in_port']
            out_port = stat.instructions[0].actions[-1].port
            actions = [parser.OFPActionOutput(out_port)]
            dpid = datapath.id
            #if stat.match['ipv4_src'] == "10.0.0.2":         // Packet rate commented
            #    print "\np0 = ", self.p0
            #    p2 = stat.packet_count
            #    print "\np2 =", p2
            #    p3 = p2-self.p0
            #    self.pkt_count = p3/10
            #    self.p0 = p2
            #    print "\nPacket rate = ", self.pkt_count
            #if stat.match['ipv4_src'] == "10.0.0.1":
            #    print "\np1 =", self.p1
            #    p4 = stat.packet_count
            #    print "\np4 =", p4
            #    p5 = p4-self.p1
            #    self.pkt_count = p5/10
            #    self.p1 = p4
            #    print "\nPacket rate = ", self.pkt_count

            

# A static condition is added to define the cookie of the flow carrying malicious packets. In a real implementation, this would be done by S-Flow or any other traffic analyzer

            if stat.match['ipv4_src']=="10.0.0.2":               #Older Version
            	print "matched H1, cookie is: ",stat.cookie
                cookie=stat.cookie
            else:                       
                cookie=1
            
# When the counter of malicious packets has reached the threshold, a message is sent to C0 with the cookie of the flow to modify
            #cookie = stat.cookie      # new version
            #if (self.pkt_count > self.threshold): #and cookie!=1):
            if (self.pkt_count > self.threshold and cookie!=1):
                if (self.cond == 0):         # Old version commented
                        print "Threshlold reached. Applying mitigation."
                        ##### Sending file content ######
                        #with open("alert01.xml") as f:
                        #    content = f.read().splitlines()
                        root = etree.parse("alert01.xml")
                        #root = content.getroot()
                        #tree = etree.ElementTree(root)
                        tree = etree.tostring(root, pretty_print= True)
                        print tree
                        #tree.write(sys.stdout)
                        #f.close()
                        #print "Passing cookie to C0 for flow redirection: ",cookie
                        #print "Passing the file content for policy enforcement: ",content
                        #params = urllib.urlencode({'Cookie' : cookie, 'Context' : 'icmp_flooding'})      # sending the cookie and attack context
                        conn = httplib.HTTPConnection("127.0.0.1", 8080) # Please hide IP here
                        #conn.request("PUT", "/simpleswitch/changevlan/0000000000000001", str(cookie))	# The cookie is passed as a string, and the request is targeted at C0
                        conn.request("PUT", "/simpleswitch/changevlan/0000000000000001", str(tree))
                        #conn.request("PUT", "/simpleswitch/changevlan/0000000000000004", str(tree))
                	#conn.request("PUT", "/simpleswitch/changevlan/0000000000000001", params)
                        response=conn.getresponse()
                    	self.cond = 1
                
                
                break
            #break
