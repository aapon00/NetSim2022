import numpy as np
import datetime
import time
from datetime import timedelta
import ipaddress
import random
from datetime import timedelta
import pandas as pd
import argparse
random.seed(10)
np.random.seed(200)
CRC_SEED = 0


ap = argparse.ArgumentParser()

ap.add_argument('-s1','--src1', type=int, help='number of destination IP')
ap.add_argument('-s','--src', type=int,  help='number of IP')
ap.add_argument('-s2','--src2', type=int, help='number of source IP')
args = ap.parse_args()


def sourceipv4(no_ips, no_ops):
    list1 = []
    for i in range(0, no_ips):
        netwrk_id = np.random.choice(range(100, 255), replace=True)
        host_id = np.random.choice(range(100, 255), replace=True)
        ip_address_gen = f'192.168.{netwrk_id}.{host_id}'
        list1.append(ip_address_gen)

    return list(np.random.choice(list1, size=no_ops, replace=True))
    return list1


def destinationipv4(no_ips, no_ops):
    list2 = []
    for i in range(0, no_ips):
        netwrk_id = np.random.choice(range(100, 255), replace=True)
        host_id = np.random.choice(range(100, 255), replace=True)
        ip_address_gen = f'192.168.{netwrk_id}.{host_id}'
        list2.append(ip_address_gen)

    return list(np.random.choice(list2, size=no_ops, replace=True))


messages = []


def time_req(num):
    timestamp_ms = 0

    gaps = np.random.weibull(1.5, num)
    for gap in gaps:
        timestamp_ms += gap
        messages.append(timestamp_ms / 1000)
    return messages


def crc1(n):
    list3 = []
    for i in random.sample(range(0, 4294967296), n):
        list3.append(i)
    return list3


def main1(src1, src, src2) -> object:

    g = sourceipv4(src2, src)
    g1 = destinationipv4(src1, src)
    s = time_req(src)
    c = crc1(src)
    return g, g1, s, c


r = main1(2, 20, 2)
new_df = pd.DataFrame(r)
a = new_df.T
a.columns = ['SourceIp', "DestinationIP", 'Time_Stamp', 'CRC']
col_list = a.SourceIp.values.tolist()
col_list1 = a.DestinationIP.values.tolist()
final = zip(col_list, col_list1)
for i, j in final:
    index = a[(a['SourceIp'] == i) & (a['DestinationIP'] == j)].index.tolist()
    a.loc[index, 'Port'] = np.random.choice(range(100, 255))
a.sort_values('Time_Stamp')
a['Port'] = a.Port.astype(str)
a['DestinationIP_&_Port'] = a['DestinationIP'] + ' : ' + a['Port']
df = a.drop(['DestinationIP', 'Port'], axis=1)
df = df[['SourceIp', 'DestinationIP_&_Port', 'Time_Stamp', 'CRC']]
df.to_csv('CRC7 '+ str(datetime.datetime.now()).split('.')[0].replace(':','-') + '.csv')
#df.to_csv('eg 1.csv')

if __name__ == '__main__':
    print(main1(args.src1, args.src, args.src2))
