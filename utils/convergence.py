import sys
import os
import pandas as pd
import re
import ipaddress
from collections import OrderedDict

pattern_re = [
        re.compile(r"addr=.\d+\.\d+\.\d+\.\d+.,length=\d+\)"),
        re.compile(r"\d+\.\d+\.\d+\.\d+.*\d+\.\d+\.\d+\.\d+")
        ]

def extract_prefix_and_mask(line):

    def get_mask(line): # line = 'x.x.x.x' or line = 24
        mask = re.search(r'\d+(?:\.\d+){3}', line)
        if not mask:
            mask = re.search(r'\d+', line)
        if mask:
            return mask.group(0)

    for comp in pattern_re:
        subline = comp.search(line)
        if subline:
            line = subline.group(0)
            prefix = re.search(r'\d+(?:\.\d+){3}', line)
            if prefix:
                span_min, span_max = prefix.span()
                prefix = prefix.group(0)
                mask = get_mask(line[span_max:])
                if mask:
                    return prefix, mask
    return (None, None)

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

if __name__ == '__main__':
    main(*sys.argv[1:])
