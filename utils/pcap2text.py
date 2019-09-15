#!/usr/bin/env python3
import sys
import ipaddress
import argparse

from ryu.lib.pcaplib import Reader
from ryu.lib.packet import packet
from ryu.lib.packet import openflow
from ryu.lib import packet as pktlib
from ryu import ofproto

class Filter:
    proto_classes = []
    specifics = []

    def match(self, pkt):
        for idx, proto in enumerate(pkt.protocols):
            if type(proto) in self.proto_classes:
                return idx


class FilterOR(Filter):

    def __init__(self, filter1, filter2):
        self._filter1 = filter1
        self._filter2 = filter2

    def match(self, pkt):
        idx1 = self._filter1.match(pkt)
        idx2 = self._filter2.match(pkt)
        if idx1 is not None and idx2 is not None:
            if idx1 > idx2:
                return idx1
            else:
                return idx2
        elif idx1 is not None:
            return idx1
        return idx2


class FilterAND(FilterOR):

    def match(self, pkt):
        idx1 = self._filter1.match(pkt)
        idx2 = self._filter2.match(pkt)
        if idx1 is not None and idx2 is not None:
            if idx1 > idx2:
                return idx1
            else:
                return idx2


class FilterANY(Filter):

    def match(self, pkt):
        return True


class SrcHostFilter(Filter):

    def __init__(self, host):
        self.host = ipaddress.ip_address(host)
        if self.host.version == 4:
            self.proto_classes = [pktlib.ipv4.ipv4]
        else:
            self.proto_classes = [pktlib.ipv6.ipv6]

    def match(self, pkt):
        for idx, proto in enumerate(pkt.protocols):
            if type(proto) in self.proto_classes and proto.src == str(self.host):
                return idx

class DstHostFilter(SrcHostFilter):

    def match(self, pkt):
        for idx, proto in enumerate(pkt.protocols):
            if type(proto) in self.proto_classes and proto.dst == str(self.host):
                return idx


class HostFilter(FilterOR):

    def __init__(self, host):
        super(HostFilter, self).__init__(SrcHostFilter(host), DstHostFilter(host))


class TCPFilter(Filter):
    proto_classes = [pktlib.tcp.tcp]


class SrcPortFilter(Filter):

    def __init__(self, port):
        self.port = port
        self.proto_classes = [pktlib.tcp.tcp, pktlib.udp.udp]

    def match(self, pkt):
        for idx, proto in enumerate(pkt.protocols):
            if type(proto) in self.proto_classes and proto.src_port == self.port:
                return idx
        return None


class DstPortFilter(SrcPortFilter):

    def match(self, pkt):
        for idx, proto in enumerate(pkt.protocols):
            if type(proto) in self.proto_classes and proto.dst_port == self.port:
                return idx
        return None


class PortFilter(FilterOR):

    def __init__(self, port):
        super(PortFilter, self).__init__(SrcPortFilter(port), DstPortFilter(port))


class OpenFlowFilter(Filter):
    proto_classes = [pktlib.openflow.openflow]
    ofmsg_types = []

    def __init__(self):
        super(OpenFlowFilter, self).__init__()

    def match(self, pkt):
        for idx, proto in enumerate(pkt.protocols):
            if type(proto) in self.proto_classes:
                if not self.ofmsg_types or type(proto.msg) in self.ofmsg_types:
                    return idx
                else:
                    return None


class OpenFlowFlowModFilter(OpenFlowFilter):
    ofmsg_types = [
            ofproto.ofproto_v1_0_parser.OFPFlowMod,
            ofproto.ofproto_v1_2_parser.OFPFlowMod,
            ofproto.ofproto_v1_3_parser.OFPFlowMod,
            ofproto.ofproto_v1_4_parser.OFPFlowMod,
            ofproto.ofproto_v1_5_parser.OFPFlowMod]


class BGPFilter(Filter):
    proto_classes = [pktlib.bgp.BGPMessage]

    def match(self, pkt):
        for idx, proto in enumerate(pkt.protocols):
            if type(proto) in self.proto_classes:
                return idx


class BGPUpdateFilter(BGPFilter):
    proto_classes = [pktlib.bgp.BGPUpdate]

    def __init__(self, fields=None):
        self.specifics = fields or []
        super(BGPUpdateFilter, self).__init__()


class Pcap2Text:

    @classmethod
    def pretty_print(cls, ts, protocols, sep='_|_', specifics=[]):
        if specifics and type(protocols) != list:
            alist = []
            for field in specifics:
                value = getattr(protocols, field)
                if value:
                    alist.append('%s=%s' % (field, value))
            print(sep.join(map(str, [ts, alist])))
        else:
            print(sep.join(map(str, [ts, protocols])))

    @classmethod
    def pcap2text(cls, pcapfile, filters, count=0, print_filter_only=False, print_filter_up=False):
        n = 0
        count = count or sys.maxsize
        for ts, buf in Reader(open(pcapfile, 'rb')):
            if n > count:
                break
            n += 1
            pkt = packet.Packet(buf)
            idx = filters.match(pkt)
            if idx is None:
                continue
            if print_filter_only:
                cls.pretty_print(ts, pkt.protocols[idx], specifics=filters.specifics)
            elif print_filter_up:
                cls.pretty_print(ts, pkt.protocols[idx:])
            else:
                cls.pretty_print(ts, pkt)
            """
            for prot in pkt.protocols:
                if type(prot) == openflow.openflow:
                    ofmsg = prot.msg
                    print(type(ofmsg), ofmsg, '\n')
            """

def filter_parser(filter_str):
    """
    Ex.
        filter_str = "host=1.0.0.1 and port=179"
        filter_str = "openflow"
        filter_str = "openflowmod"
        filter_str = "bgpupdate,nlri"
    """
    return FilterANY()

def build_args_parser():
    parser = argparse.ArgumentParser(description='Print pcap file to text')
    parser.add_argument('filename', metavar='filename', type=str, help='pcap file')
    parser.add_argument('-c', help='count')
    parser.add_argument('-z', dest='formats', type=str,
            choices=['all', 'match', 'up'],
            help='print output format. select full to print the full packet or match to print what matched only')
    parser.add_argument('-t', dest='proto', type=str,
            choices=['tcp', 'udp', 'bgp', 'openflow', 'ipv4', 'ipv6', 'icmp'],
            help='protocol filters. valid values: tcp, udp, bgp, openflow, ipv4, ipv6')
    parser.add_argument('-p', dest='port', type=int, help='port that defines the protocol')
    parser.add_argument('-f', dest='filters', type=str, default='', help='filter. more to come soon')
    return parser.parse_args()

if __name__ == '__main__':
    args = build_args_parser()
    filename = args.filename
    proto = args.proto
    port = args.port
    filter_str = args.filters
    formats = args.formats
    if proto == 'tcp':
        filters = TCPFilter()
    elif proto == 'udp':
        filters = FilterANY()
    elif proto == 'bgp':
        if port:
            pktlib.bgp.TCP_SERVER_PORT = port
        filters = PortFilter(port)
        if 'update' in filter_str:
            filters = BGPUpdateFilter()
        elif 'nlri' in filter_str:
            filters = BGPUpdateFilter(['nlri'])
    elif proto == 'openflow':
        filters = OpenFlowFilter()
        if port:
            ryu.ofproto.ofproto.common.OFP_TCP_PORT = port
        if 'flowmod' in filter_str:
            filters = OpenFlowFlowModFilter()
    else:
        filters = FilterANY()

    if formats == 'match':
        Pcap2Text.pcap2text(filename, filters, print_filter_only=True)
    elif formats == 'up':
        Pcap2Text.pcap2text(filename, filters, print_filter_up=True)
    else:
        Pcap2Text.pcap2text(filename, filters)
    #filters = HostFilter('192.168.200.1')
    #filters = DstHostFilter('192.168.200.1')
    #filters = FilterAND(HostFilter('192.168.200.1'), DstPortFilter(6653))
