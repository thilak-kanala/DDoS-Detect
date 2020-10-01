import os
import pandas as pd
import time
import numpy as np
import time

def hex_to_int(hex):
	return int(hex, 16)

def ip_len(ip):
	ip = str(ip).split('.')
	length = 0
	for i in ip:
		length += len(i)
	return length

BATCH_SIZE = 100

PCAP_COLUMNS = ['ip.proto', 'ip.src.len.mean', 'ip.src.len.median', 'ip.src.len.var', 'ip.src.len.std', 'ip.src.len.entropy', 'ip.src.len.cv', 'ip.src.len.cvq', 'ip.src.len.rte', 'ip.dst.len.mean', 'ip.dst.len.median', 'ip.dst.len.var', 'ip.dst.len.std', 'ip.dst.len.entropy', 'ip.dst.len.cv', 'ip.dst.len.cvq', 'ip.dst.len.rte', 'sport.mean', 'sport.median', 'sport.var', 'sport.std', 'sport.entropy', 'sport.cv', 'sport.cvq', 'sport.rte', 'dport.mean', 'dport.median', 'dport.var', 'dport.std', 'dport.entropy', 'dport.cv', 'dport.cvq', 'dport.rte', 'tcp.flags.mean', 'tcp.flags.median', 'tcp.flags.var', 'tcp.flags.std', 'tcp.flags.entropy', 'tcp.flags.cv', 'tcp.flags.cvq', 'tcp.flags.rte']

PCAP_COLUMNS_DICT = {key: None for key in PCAP_COLUMNS}

# udp_path : path of .csv file of udp packets
# tcp_path : path of .csv file of tcp packets
# status : 'benign' / 'malware' 
# returns the final dataframe for 1 pcap file
def generate_batch_df(df, status):
	# add ip.len column
	# ip_src_len = [ip_len(i) for i in df['ip.src']] 
	# df['ip.src.len'] = ip_src_len
	df['ip.src.len'] = df['ip.src'].apply(ip_len)
	# ip_dst_len = [ip_len(i) for i in df['ip.dst']] 
	# df['ip.dst.len'] = ip_src_len
	df['ip.dst.len'] = df['ip.dst'].apply(ip_len)

	# remove ip.src and ip.dst
	df = df.drop(['ip.src', 'ip.dst'], axis = 1)

	# drop nas
	df = df.fillna(int(0))

	# convert all columns data type to int
	df = df.astype(int)

	# sample random rows from df (all rows)
	df = df.sample(frac = .5, replace = False)

	# final dataframe with summary of pcap file
	df_summary = pd.DataFrame(PCAP_COLUMNS_DICT, index = [0])

	# calculate summary statistics
	df_summary['ip.proto'] = df['ip.proto'].mean()
	df_summary['ip.src.len.mean'] = df['ip.src.len'].mean()
	df_summary['ip.src.len.median'] = df['ip.src.len'].median()
	df_summary['ip.src.len.var'] = df['ip.src.len'].var()
	df_summary['ip.src.len.std'] = df['ip.src.len'].std()
	df_summary['ip.src.len.entropy'] = int(0)
	df_summary['ip.src.len.cv'] = df_summary['ip.src.len.std'][0] / df_summary['ip.src.len.mean'][0]
	df_summary['ip.src.len.cvq'] = int(0)
	df_summary['ip.src.len.rte'] = df['ip.src.len'].nunique() / df['ip.src.len'].size

	df_summary['ip.dst.len.mean'] = df['ip.dst.len'].mean()
	df_summary['ip.dst.len.median'] = df['ip.dst.len'].median()
	df_summary['ip.dst.len.var'] = df['ip.dst.len'].var()
	df_summary['ip.dst.len.std'] = df['ip.dst.len'].std()
	df_summary['ip.dst.len.entropy'] = int(0)
	df_summary['ip.dst.len.cv'] = df_summary['ip.dst.len.std'][0] / df_summary['ip.dst.len.mean'][0]
	df_summary['ip.dst.len.cvq'] = int(0)
	df_summary['ip.dst.len.rte'] = df['ip.dst.len'].nunique() / df['ip.dst.len'].size

	df_summary['sport.mean'] = df['src.port'].mean()
	df_summary['sport.median'] = df['src.port'].median()
	df_summary['sport.var'] = df['src.port'].var()
	df_summary['sport.std'] = df['src.port'].std()
	df_summary['sport.entropy'] = int(0)
	df_summary['sport.cv'] = df_summary['sport.std'][0] / df_summary['sport.mean'][0]
	df_summary['sport.cvq'] = int(0)
	df_summary['sport.rte'] = df['src.port'].nunique() / df['src.port'].size

	df_summary['dport.mean'] = df['dst.port'].mean()
	df_summary['dport.median'] = df['dst.port'].median()
	df_summary['dport.var'] = df['dst.port'].var()
	df_summary['dport.std'] = df['dst.port'].std()
	df_summary['dport.entropy'] = int(0)
	df_summary['dport.cv'] = df_summary['dport.std'][0] / df_summary['dport.mean'][0]
	df_summary['dport.cvq'] =  int(0)
	df_summary['dport.rte'] = df['dst.port'].nunique() / df['dst.port'].size

	df_summary['tcp.flags.mean'] = df['tcp.flags'].mean()
	df_summary['tcp.flags.median'] = df['tcp.flags'].median()
	df_summary['tcp.flags.var'] = df['tcp.flags'].var()
	df_summary['tcp.flags.std'] = df['tcp.flags'].std()
	df_summary['tcp.flags.entropy'] = int(0)
	df_summary['tcp.flags.cv'] = df_summary['tcp.flags.std'][0] / df_summary['tcp.flags.mean'][0]
	df_summary['tcp.flags.cvq'] = int(0)
	df_summary['tcp.flags.rte'] = df['tcp.flags'].nunique() / df['tcp.flags'].size

	df_summary['status'] = status
	return df_summary

def combine_tcp_udp_dataframes(tcp_path, udp_path):
	df_tcp = pd.read_csv(tcp_path)
	df_udp = pd.read_csv(udp_path)

	# drop column frame.number
	# df_tcp = df_tcp.drop('frame.number', axis = 1)
	# df_udp = df_udp.drop('frame.number', axis = 1)

	# drop tcp.flags in udp packets
	df_udp["tcp.flags"] = df_udp["tcp.flags"].fillna(int(0))

	# rename port columns to faciliatate combining of data frames 
	df_tcp = df_tcp.rename(columns = {'tcp.srcport' : 'src.port', 'tcp.dstport' : 'dst.port'})
	df_udp = df_udp.rename(columns = {'udp.srcport' : 'src.port', 'udp.dstport' : 'dst.port'})

	# convet tcp.flags from hex to int
	df_tcp['tcp.flags'] = df_tcp['tcp.flags'].apply(hex_to_int)

	# combine tcp and udp df to form df
	df_concat = [df_tcp, df_udp]
	df = pd.concat(df_concat, ignore_index = True)

	df = df.sort_values('frame.number', ascending = True, ignore_index = True)
	df = df.drop('frame.number', axis = 1)

	return df

# ===================== GENERATE .CSV FILE LIST ===================== 
os.system('mkdir CSV_FILES_PATH_LIST')
# find benign tcp .csv files
os.system('find ./CSV_FILES/BENIGN -name "*_tcp.csv" > ./CSV_FILES_PATH_LIST/benign_tcp_testdata_file_list.txt')

# find benign udp .csv files
os.system('find ./CSV_FILES/BENIGN -name "*_udp.csv" > ./CSV_FILES_PATH_LIST/benign_udp_testdata_file_list.txt')

# find malware tcp .csv files
os.system('find ./CSV_FILES/MALWARE -name "*_tcp.csv" > ./CSV_FILES_PATH_LIST/malware_tcp_testdata_file_list.txt')

# find malware udp .csv files
os.system('find ./CSV_FILES/MALWARE -name "*_udp.csv" > ./CSV_FILES_PATH_LIST/malware_udp_testdata_file_list.txt')

os.system('mkdir CSV_FILES_BATCH')

# =======================Process benign tcp and udp .csv files======================
tcp_file_list = open('./CSV_FILES_PATH_LIST/benign_tcp_testdata_file_list.txt').read()
udp_file_list = open('./CSV_FILES_PATH_LIST/benign_udp_testdata_file_list.txt').read()

tcp_file_list = tcp_file_list.split('\n')[0:-1]
udp_file_list = udp_file_list.split('\n')[0:-1]

tcp_file_list.sort(key = lambda x: int(x.split('/')[-1].split('_')[0])) 
udp_file_list.sort(key = lambda x: int(x.split('/')[-1].split('_')[0])) 


b = 0
start_time = time.time()
for (tcp_file_path, udp_file_path, i) in zip(tcp_file_list, udp_file_list, range(len(tcp_file_list))):

	df_benign = pd.DataFrame(PCAP_COLUMNS_DICT, index = [0])
	df = combine_tcp_udp_dataframes(tcp_file_path, udp_file_path)

	# pick BATCH_SIZE packets at a time
	for j in range(0, (df.shape[0] - (df.shape[0] % BATCH_SIZE)), BATCH_SIZE):
		df_temp = df[j : j + BATCH_SIZE]
		df_benign = df_benign.append(generate_batch_df(df_temp.copy(), 'benign'), ignore_index = True)

	# pick the left over packets (after forming batches of BATCH_SIZE)
	df_temp = df[(df.shape[0] - (df.shape[0] % BATCH_SIZE)) : df.shape[0]]
	df_temp = df[j : j + BATCH_SIZE]
	df_benign = df_benign.append(generate_batch_df(df_temp.copy(), 'benign'), ignore_index = True)
	print(f"benign : {i}")
	# drop the 1st row
	df_benign = df_benign.drop([0], axis = 0)
	df_benign.to_csv(f"./CSV_FILES_BATCH/{i}_benign.csv", index = False)

print(time.time()- start_time)

# =======================Process malware tcp and udp .csv files======================
tcp_file_list = open('./CSV_FILES_PATH_LIST/malware_tcp_testdata_file_list.txt').read()
udp_file_list = open('./CSV_FILES_PATH_LIST/malware_udp_testdata_file_list.txt').read()

tcp_file_list = tcp_file_list.split('\n')[0:-1]
udp_file_list = udp_file_list.split('\n')[0:-1]

tcp_file_list.sort(key = lambda x: int(x.split('/')[-1].split('_')[0])) 
udp_file_list.sort(key = lambda x: int(x.split('/')[-1].split('_')[0])) 


b = 0
start_time = time.time()
for (tcp_file_path, udp_file_path, i) in zip(tcp_file_list, udp_file_list, range(len(tcp_file_list))):

	df_malware = pd.DataFrame(PCAP_COLUMNS_DICT, index = [0])
	df = combine_tcp_udp_dataframes(tcp_file_path, udp_file_path)

	# pick BATCH_SIZE packets at a time
	for j in range(0, (df.shape[0] - (df.shape[0] % BATCH_SIZE)), BATCH_SIZE):
		df_temp = df[j : j + BATCH_SIZE]
		df_malware = df_malware.append(generate_batch_df(df_temp.copy(), 'malware'), ignore_index = True)

	# pick the left over packets (after forming batches of BATCH_SIZE)
	df_temp = df[(df.shape[0] - (df.shape[0] % BATCH_SIZE)) : df.shape[0]]
	df_temp = df[j : j + BATCH_SIZE]
	df_malware = df_malware.append(generate_batch_df(df_temp.copy(), 'malware'), ignore_index = True)
	print(f"malware : {i}")
	# drop the 1st row
	df_malware = df_malware.drop([0], axis = 0)
	df_malware.to_csv(f"./CSV_FILES_BATCH/{i}_malware.csv", index = False)

print(time.time()- start_time)


# ============================================================================================================
# # # Process test tcp and udp .csv files
# tcp_file_path = './Dataset/testdata2/benign/p2pbox1/p2pbox1_1_tcp.csv'
# udp_file_path = './Dataset/testdata2/benign/p2pbox1/p2pbox1_1_udp.csv'

# # tcp_file_list = tcp_file_list.split('\n')[0:-1]
# # udp_file_list = udp_file_list.split('\n')[0:-1]

# # tcp_file_list.sort(key = lambda x: int(x.split('/')[-1].split('_')[0])) 
# # udp_file_list.sort(key = lambda x: int(x.split('/')[-1].split('_')[0])) 

# df_test_batch = pd.DataFrame(PCAP_COLUMNS_DICT, index = [0])
# df = combine_tcp_udp_dataframes(tcp_file_path, udp_file_path)

# # pick BATCH_SIZE packets at a time
# for j in range(0, (df.shape[0] - (df.shape[0] % BATCH_SIZE)), BATCH_SIZE):
# 	df_temp = df[j : j + BATCH_SIZE]
# 	df_test_batch = df_test_batch.append(generate_batch_df(df_temp.copy(), 'test'), ignore_index = True)

# # pick the left over packets (after forming batches of BATCH_SIZE)
# df_temp = df[(df.shape[0] - (df.shape[0] % BATCH_SIZE)) : df.shape[0]]
# df_temp = df[j : j + BATCH_SIZE]
# df_test_batch = df_test_batch.append(generate_batch_df(df_temp.copy(), 'test'), ignore_index = True)

# df_test_batch = df_test_batch.drop([0], axis = 0)
# df_test_batch.to_csv('./Dataset/testdata2/benign/p2pbox1/p2pbox1_batch.csv', index = False)

# # drop the 1st row
# df_benign = df_benign.drop([0], axis = 0)
# df_benign.to_csv('./p2pbox1_1_batch.csv', index = False)
# ========================================================================================================