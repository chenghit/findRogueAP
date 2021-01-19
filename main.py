#!/usr/bin/env python3

import re
import os
from datetime import datetime

import click
import pandas as pd
# import pysnooper

# @pysnooper.snoop()
def buildRogueDetectDf(txt_path):
    names = ['MAC_Address', 'Class', 'State', 'Det_Aps', 'Rogue_Clients',
                      'Highest_RSSI_Det-Ap', 'h_RSSI', 'h_Channel',
                      'Second_Highest_RSSI_Det-Ap', 's_RSSI', 's_Channel']
    pattern_line = re.compile(r'^(?:[0-9a-fA-F]:?){12}\s+(Unclassified|Malicious|Pending)')
    interim_path = 'interim.txt'
    interim_file = open(interim_path, 'w')
    with open(txt_path) as f:
        for line in f:
            l = re.match(pattern_line, line)
            if l is not None:
                interim_file.writelines(line)
    interim_file.close()
    df = pd.read_table(interim_path, sep='\s+', names=names)
    df['MAC_Address'] = df['MAC_Address'].str.upper()
    return df

# @pysnooper.snoop()
def buildApMacNameDict(txt_path):
    pattern = re.compile(r'^(\S+)\s+((?:[0-9a-fA-F]:?){12})\s+1\s+ENABLED')
    ap_mac_name = {}
    with open(txt_path) as f:
        for line in f:
            m = re.match(pattern, line)
            if m is not None:
                ap_mac_name.update({m.group(2): m.group(1)})
    return ap_mac_name

# @pysnooper.snoop()
def replaceApMac(df, _dict):
    for key, value in _dict.items():
        df.replace(key, value, inplace=True)
    return df

# @pysnooper.snoop()
def buildSsidNameDict(table_path, version=1):
    if version == 1:
        names = ['Threat Level', 'Rogue AP MAC address', 'Type', 'Connection',
             'Detecting AP', 'Detecting AP Site', 'RSSI', 'SSID', 'Last Reported']
    elif version == 2:
        names = ['Threat Level', 'Rogue AP MAC address', 'Type', 'Detecting AP',
             'Detecting AP Site', 'RSSI', 'SSID', 'Clients', 'Last Reported']
    else:
        raise Exception(u'DNAC 版本只能为 1 或者 2！默认为 1')

    suffix = os.path.splitext(table_path)[-1][1:]

    if suffix == 'csv':
        df = pd.read_csv(table_path, names=names)
    elif suffix == 'xls':
        df = pd.read_excel(table_path, names=names)
    else:
        raise Exception(u'请将 DNAC 报表转换为 CSV 或 XLS 格式')

    df = df[['Rogue AP MAC address', 'SSID']]
    _dict = df.set_index('Rogue AP MAC address').T.to_dict('record')[0]
    return _dict

# @pysnooper.snoop()
def insertSsidName(df, _dict):
    ssids = []
    for item in df['MAC_Address']:
        if item in _dict:
            ssids.append(_dict[item])
        else:
            ssids.append('')
    df['SSID'] = ssids
    time_stamp = datetime.now()
    df.to_excel('Rogue_report_' + time_stamp.strftime('%Y%m%d_%H%M%S') + '.xlsx',
                index=False, engine='openpyxl')


@click.command()
@click.option('--txt', help='''
txt或者log文件路径，包含WLC "show advanced 802.11a summary"
和"show rogue ap summary"结果。\n
File path of a .txt or .log file which includes the results of
"show advanced 802.11a summary" and "show rogue ap summary".
''')
@click.option('--table', help='''
csv或者xls文件路径，DNAC RogueManagement Dashboard报表，默认
Columns复制即可，请勿自定义列。\n
File path of a .csv or .xls file which includes the contents 
copied from RogueManagement Dashboard on DNAC. 
Do NOT modify the columns on DNAC!
''')
@click.option('--version', default=1,
              help='DNAC main version number. 1 or 2. Default is 1.',
              type=int)
def main(txt, table, version=1):

    # Find the mapping of rogue ap and detect ap, then build a dataframe
    df_rogue1 = buildRogueDetectDf(txt)

    # Find the mapping of ap_mac_addr and ap_name, then build a dict
    dict_ap_name = buildApMacNameDict(txt)

    # Search the ap_name dict then replace ap_mac_addr with ap_name in the dataframe
    df_rogue2 = replaceApMac(df_rogue1, dict_ap_name)

    # Find the mapping of rogue_mac and ssid_name, then build a dict
    dict_ssid_name = buildSsidNameDict(table, version)

    # Search the ssid_name dict then insert a column and input ssid_name along with
    # rogue_mac in the dataframe, and save a xls file on the disk.
    insertSsidName(df_rogue2, dict_ssid_name)


if __name__ == '__main__':
    main()

