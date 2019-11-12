import sys
import os
import fnmatch
import pandas as pd
import re
import ipaddress
from collections import OrderedDict
import argparse

from ryu.lib.pcaplib import Reader
from ryu.lib.packet import packet
from ryu.lib import packet as packetlib
from ryu import ofproto


pattern_re = [
        re.compile(r"addr=.\d+\.\d+\.\d+\.\d+.,length=\d+\)"),
        re.compile(r"\d+\.\d+\.\d+\.\d+.*\d+\.\d+\.\d+\.\d+")
        ]

def files_by_patterns(root, patterns="*", single_level=False, yield_folders=False):
    patterns = patterns.split(';')
    for path, subdirs, files in os.walk(root):
        if yield_folders:
            files.extend(subdirs)
        files.sort()
        for name in files:
            for pattern in patterns:
                if fnmatch.fnmatch(name, pattern):
                    yield os.path.join(path, name)
                    break
        if single_level:
            break


def extract_prefixes(line):
    """Extract prefixes from a text string.
    Ex. 'abcd 1.2.3.4/24', 'adbc 1.2.3.4,length=24', 'abc 1.2.3.4, 255.255.255.0'
    """

    patterns_re = [
        re.compile(r'\d+\.\d+\.\d+\.\d+/\d+'),
        re.compile(r"addr=.\d+\.\d+\.\d+\.\d+.,length=\d+\)"),
        re.compile(r"\d+\.\d+\.\d+\.\d+.*\d+\.\d+\.\d+\.\d+")
    ]

    prefix_re = re.compile(r'\d+(?:\.\d+){3}')
    prefixes = []

    def get_mask(line): # line = 'x.x.x.x' or line = 24
        mask = prefix_re.search(line) or re.search(r'\d+', line)
        if mask:
            return mask.group(0)

    for comp in patterns_re:
        subline = comp.search(line)
        if subline:
            line = subline.group(0)
            if '/' in line:
                return [ipaddress.ip_network(line)]
            prefix = prefix_re.search(line)
            if prefix:
                span_min, span_max = prefix.span()
                prefix = prefix.group(0)
                mask = get_mask(line[span_max:])
                if mask:
                    return [ipaddress.ip_network('%s/%s' % (prefix, mask))]
    return []


experiments = [('Expr1', "500-2"), ('Expr2', "1000-10"), ('Expr3', "2000-10"), ('Expr4', "5000-5")]

from datetime import datetime
def parse_timestamp(line):
    fmt = '%Y-%m-%d %H:%M:%S,%f'
    t = datetime.strptime(line, fmt)
    return t.timestamp()

def get_announced_prefixes(path, expr_pattern):

    prefixes = OrderedDict()
    expr_pattern = 'bgpreplay*%s*.log' % expr_pattern
    for fname in files_by_patterns(path, expr_pattern):
        with open(fname, 'r') as f:
            for line in f:
                ts = parse_timestamp(line[:23])
                prefix = extract_prefixes(line)
                if prefix:
                    prefixes[prefix[0]] = ts
        break
    return prefixes


def process_raw_pcap(root, expr_name, expr_pattern):
    expr_pattern = "*%s*.pcap" % expr_pattern
    for fname in files_by_pattern(root, expr_pattern):
        pcapreader = PcapReader(fname)
        for line in pcapreader.read_lines():
            pass


def parse_raw_pcap(fname, proto_class, non_default_bgp_port=None):
    def get_protocols(buf, proto_class, non_default_bgp_port):
        pkt = packet.Packet(buf)
        protos = [proto for proto in pkt.protocols if type(proto) == proto_class]
        if non_default_bgp_port and not protos:
            packetlib.bgp.TCP_SERVER_PORT = non_default_bgp_port
            pkt = packet.Packet(buf)
            packetlib.bgp.TCP_SERVER_PORT = 179
            return [proto for proto in pkt.protocols if type(proto) == proto_class]
        else:
            return [proto for proto in pkt.protocols if type(proto) == proto_class]

    data = []
    try:
        for ts, buf in Reader(open(fname, 'rb')):
            for proto in get_protocols(buf, proto_class, non_default_bgp_port=non_default_bgp_port):
                yield ts, proto
                #data.append((ts, proto))
    except Exception as e:
        print(e)
    return data


def parse_bgp_data(pcapfile, prefixes):
    data = [None] * len(prefixes)
    for ts, pkt in parse_raw_pcap(pcapfile, packetlib.bgp.BGPUpdate, 9179):
        for prefix in pkt.nlri:
            prefix = ipaddress.ip_network(prefix.prefix)
            if prefix in prefixes:
                data[prefixes.index(prefix)] = float(ts)
                break
    return data


def parse_openflow_data(pcapfile, prefixes):
    data = [None] * len(prefixes)
    for ts, pkt in parse_raw_pcap(pcapfile, packetlib.openflow.openflow):
        msg = pkt.msg
        if type(msg) == ofproto.ofproto_v1_3_parser.OFPFlowMod:
            prefixes_ = extract_prefixes(str(msg))
            for prefix in prefixes_:
                if prefix in prefixes:
                    data[prefixes.index(prefix)] = float(ts)
                    break
                else:
                    print(ts, prefix)
    return data

packetlib.bgp.TCP_SERVER_PORT = 9179

def make_cdf_graph(df):
    hosts = ['m169', 'm17d', 'm17c']
    labels = ['openflow', 'bgp']

    fig = go.Figure()
    for host in hosts:
        dp1 = df[labels[0]] - df[labels[1]]
        dp1 = dp1.values
        dp1 = np.sort(dp1)
        fig.add_scatter(x=dp1, y=np.linspace(0, 1, len(dp1)))


def process_expriment_data(path, expr_name, expr_pattern):
    prefixes = get_announced_prefixes(path, expr_pattern)
    df = pd.DataFrame({'prefix': list(prefixes.keys()), 'announce_ts': list(prefixes.values())})
    for fname in files_by_patterns(path, '*bgp*%s.pcap' % expr_pattern):
        field_name = os.path.basename(fname)[:8]
        print(fname, field_name)
        data = parse_bgp_data(fname, list(prefixes.keys()))
        df1 = pd.DataFrame({field_name: data})
        df = df.join(df1)

    for fname in files_by_patterns(path, '*openflow*%s.pcap' % expr_pattern):
        field_name = os.path.basename(fname)[:13]
        print(fname, field_name)
        data = parse_openflow_data(fname, list(prefixes.keys()))
        df1 = pd.DataFrame({field_name: data})
        df = df.join(df1)

    df.to_csv('%s-convergence.txt' % expr_name)
    diff = df['m169-openflow'] - df['m169-bgp']
    df2 = pd.DataFrame({'diff': diff, 'prefix': df['prefix']})
    df2.to_csv('m169-diff.txt')


def main(bgpfile, *of_files):
    cols = ['prefix', 'bgp_ts']
    prefixes = OrderedDict()
    with open(bgpfile, 'r') as f:
        for line in f:
            ts, text = line.split('_|_')
            prefix, mask = extract_prefix_and_mask(text)
            if prefix and mask:
                prefix = ipaddress.ip_network('%s/%s' % (prefix, mask))
                all_ts = prefixes.get(prefix, [])
                all_ts.append(float(ts))
                prefixes[prefix] = all_ts
    for i, of_file in enumerate(of_files, 1):
        code = re.search(r'm\w\w\w', of_file)
        if code:
            code = code.group(0)
        else:
            code = os.path.basename(of_file)
        cols.append(code)
        with open(of_file, 'r') as f:
            for line in f:
                ts, text = line.split('_|_')
                prefix, mask = extract_prefix_and_mask(text)
                if prefix and mask:
                    prefix = ipaddress.ip_network('%s/%s' % (prefix, mask))
                    all_ts = prefixes.get(prefix, [])
                    all_ts.append(float(ts))
                    prefixes[prefix] = all_ts
    df = pd.DataFrame(columns=cols)
    for prefix, tss in prefixes.items():
        row = {}
        for i, col in enumerate(cols[1:]):
            if i < len(tss):
                row[col] = tss[i]
        #if len(row.keys()) == len(cols) - 1:
        row['prefix'] = str(prefix)
        df = df.append(row, ignore_index=True)

    df['m169_diff'] = df['m169'].sub(df['bgp_ts'])
    df['m17d_diff'] = df['m17d'].sub(df['bgp_ts'])
    df['m17c_diff'] = df['m17c'].sub(df['bgp_ts'])
    #print(diff)
    df.to_csv('convergence.txt')

import plotly.graph_objects as go

def make_cdf_graph():
    fig = go.Figure()
    fib.write_image('/home/ubuntu/trungth/thesis/images/convergence.pdf')


parser = argparse.ArgumentParser()
parser.add_argument("path", help="directory containing experiment data")
parser.add_argument('expr', nargs="+", help="experiment name and pattern, e.g. Expr1,500-2")
args = parser.parse_args()

if __name__ == '__main__':
    path = args.path
    expriments = args.expr or []
    for expr in expriments:
        expr_name, expr_pattern = expr.split(',')
        process_expriment_data(path, expr_name, expr_pattern)
