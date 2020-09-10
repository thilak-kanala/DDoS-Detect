import os
import sys
import pandas as pd
import pickle
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

absolute_path_for_pcap_file = str(sys.argv[1])

print('\n== Please wait upto 2 minutes, ignore the warnings ==\n')

os.system('mkdir TEMPORARY_FILES')
os.system('mkdir TEMPORARY_FILES/CSV_FILES')
os.system('mkdir TEMPORARY_FILES/FINAL_OUTPUT_TEMP')


# =========================== FEATURE EXTRACTION ===========================

print('Extracting Features...')

os.system(f'tshark -r {absolute_path_for_pcap_file} -Y "tcp and not _ws.malformed and not icmp" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags -e ip.proto -E header=y -E separator=, > ./TEMPORARY_FILES/CSV_FILES/_tcp.csv')

os.system(f'tshark -r {absolute_path_for_pcap_file} -Y "udp and not _ws.malformed and not icmp" -T fields -e frame.number -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e tcp.flags -e ip.proto -E header=y -E separator=, > ./TEMPORARY_FILES/CSV_FILES/_udp.csv')

print('Extracting Features... DONE!')

# =========================== FEATURE ENGINEERING ===========================
def hex_to_int(hex):
	return int(hex, 16)

def ip_len(ip):
	ip = str(ip).split('.')
	length = 0
	for i in ip:
		length += len(i)
	return length

# udp_path : path of .csv file of udp packets
# tcp_path : path of .csv file of tcp packets
# returns the final dataframe for 1 pcap file
def generate_batch_df(df):
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

	# convert tcp.flags from hex to int
	df_tcp['tcp.flags'] = df_tcp['tcp.flags'].apply(hex_to_int)

	# combine tcp and udp df to form df
	df_concat = [df_tcp, df_udp]
	df = pd.concat(df_concat, ignore_index = True)

	df = df.sort_values('frame.number', ascending = True, ignore_index = True)
	return df

BATCH_SIZE = 100

PCAP_COLUMNS = ['ip.proto', 'ip.src.len.mean', 'ip.src.len.median', 'ip.src.len.var', 'ip.src.len.std', 'ip.src.len.entropy', 'ip.src.len.cv', 'ip.src.len.cvq', 'ip.src.len.rte', 'ip.dst.len.mean', 'ip.dst.len.median', 'ip.dst.len.var', 'ip.dst.len.std', 'ip.dst.len.entropy', 'ip.dst.len.cv', 'ip.dst.len.cvq', 'ip.dst.len.rte', 'sport.mean', 'sport.median', 'sport.var', 'sport.std', 'sport.entropy', 'sport.cv', 'sport.cvq', 'sport.rte', 'dport.mean', 'dport.median', 'dport.var', 'dport.std', 'dport.entropy', 'dport.cv', 'dport.cvq', 'dport.rte', 'tcp.flags.mean', 'tcp.flags.median', 'tcp.flags.var', 'tcp.flags.std', 'tcp.flags.entropy', 'tcp.flags.cv', 'tcp.flags.cvq', 'tcp.flags.rte']

PCAP_COLUMNS_DICT = {key: None for key in PCAP_COLUMNS}

df_batch = pd.DataFrame(PCAP_COLUMNS_DICT, index = [0])

df = combine_tcp_udp_dataframes('./TEMPORARY_FILES/CSV_FILES/_tcp.csv', './TEMPORARY_FILES/CSV_FILES/_udp.csv')

print('Creating Batches...')

# pick BATCH_SIZE packets at a time
batch_number = -1
for j in range(0, (df.shape[0] - (df.shape[0] % BATCH_SIZE)), BATCH_SIZE):
	# batch_number += 1
	# df[j : j + BATCH_SIZE]['batch.number'] = batch_number
	df_temp = df[j : j + BATCH_SIZE]
	df_batch = df_batch.append(generate_batch_df(df_temp.copy()), ignore_index = True)

# pick the left over packets (after forming batches of BATCH_SIZE)
df_temp = df[(df.shape[0] - (df.shape[0] % BATCH_SIZE)) : df.shape[0]]

# batch_number += 1
# df[j : j + BATCH_SIZE]['batch.number'] = batch_number
df_temp = df[j : j + BATCH_SIZE]
df_batch = df_batch.append(generate_batch_df(df_temp.copy()), ignore_index = True)

# drop the 1st row
df_batch = df_batch.drop([0], axis = 0)

df.to_csv('./CSV_FILES_BATCH/_NETWORK_TRAFFIC.csv', index = False)
df_batch.to_csv("./CSV_FILES_BATCH/_BATCH.csv", index = False)

print('Creating Batches... DONE!')

# ============== MACHINE LEARNING - CLASSIFICATION ==============

print('Classifying...')

drop = ['ip.src.len.entropy', 'ip.src.len.cvq','ip.dst.len.entropy', 'ip.dst.len.cvq', 'sport.entropy', 'sport.cvq', 'dport.entropy', 'dport.cvq', 'tcp.flags.entropy', 'tcp.flags.cvq']

X_drop_columns_more = ['ip.src.len.median', 'ip.src.len.var', 'ip.src.len.std','ip.src.len.cv', 'ip.src.len.rte', 'ip.dst.len.median', 'ip.dst.len.var', 'ip.dst.len.std', 'ip.dst.len.cv', 'ip.dst.len.rte','tcp.flags.mean', 'tcp.flags.median', 'tcp.flags.var', 'tcp.flags.std', 'tcp.flags.entropy', 'tcp.flags.cv', 'tcp.flags.cvq', 'tcp.flags.rte']

batch_network_traffic_classifier = pickle.load(open("batch_network_traffic_classifier.sav", 'rb'))

df_batch = pd.read_csv('./CSV_FILES_BATCH/_BATCH.csv')
df_network_traffic = pd.read_csv('./CSV_FILES_BATCH/_NETWORK_TRAFFIC.csv')

df_batch = df_batch.fillna(0)
df_network_traffic = df_network_traffic.fillna(0)

X = df_batch.drop(drop + X_drop_columns_more, axis = 1).values
X = X.astype(float)

scaler = StandardScaler()
scaler.fit(X)
X_scaled = scaler.transform(X)

y_pred = batch_network_traffic_classifier.predict(X_scaled)
print(f"total malware batches : {sum(y_pred == 1)}")
print(f"total benign batches: {sum(y_pred == 0)}")

batch_number = -1
for (i,j) in zip(y_pred, range(0, (df_network_traffic.shape[0] - (df_network_traffic.shape[0] % BATCH_SIZE)), BATCH_SIZE)):
	if (i == 0):
		status = 'benign'
	if (i == 1):
		status = 'ddos_attack'
	df_temp = df_network_traffic[j : j + BATCH_SIZE]
	df_temp.loc[:,('status')] = status
	batch_number += 1
	df_temp[['frame.number', 'ip.src', 'ip.dst', 'status']].to_csv(f'./TEMPORARY_FILES/FINAL_OUTPUT_TEMP/{batch_number}.csv') 

if (y_pred[-1] == 0):
	status = 'benign'
if (y_pred[-1] == 1):
	status = 'ddos_attack'

# pick the left over packets (after forming batches of BATCH_SIZE)
df_temp = df_network_traffic[(df.shape[0] - (df.shape[0] % BATCH_SIZE)) : df.shape[0]]
batch_number += 1
df_temp = df_network_traffic[j : j + BATCH_SIZE]
df_temp.loc[:,('status')] = status
df_temp[['frame.number', 'ip.src', 'ip.dst', 'status']].to_csv(f'./TEMPORARY_FILES/FINAL_OUTPUT_TEMP/{batch_number}.csv') 

file_list = os.scandir('./TEMPORARY_FILES/FINAL_OUTPUT_TEMP')

df_combined = pd.concat([pd.read_csv(f.path) for f in file_list ], ignore_index = True)
df_combined.drop(['Unnamed: 0'], axis = 1, inplace = True)
# df_combined.to_csv( "./FINAL_OUTPUT.csv", index = False)
df_combined = df_combined.sort_values('frame.number', ascending = True, ignore_index = True)
df_combined.to_csv(r'./FINAL_OUTPUT.txt', index=None, sep='|', mode='a')

print('\n== Classifying... DONE! ==\n')
print('\n== The final classification is in `FINAL_OUTPUT.txt` ==\n')
