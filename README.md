# DDOS Detection

## Libraries Used
`tshark` [sudo apt-get install wireshark]
`pandas`
`os`
`numpy`
`sklearn`
`pickle`
`sys`
`time`


## Pipeline for training
1.  feature_extraction [python script]
	a. We use the tool `tshark` to extract required features from the .pcap files.
       b.  TCP and UDP protocol packets are extracted into separate CSV files and combined at a later stage in the pipeline.

2.  feature_engineering [python script]
a. The tcp and udp packets of the same session (each pcap file) are combined back into their original structure using the `frame.number` attribute to restore packet order integrity. The combined data is stored in a `pandas data frame`
b. This data is then split into `batches` (batch size = 100) to analyze the packets in the form of clusters.
c.  To ensure proper variability of data in each cluster `bootstrap sampling` is applied to each batch.
d.  Summary statistics (such as mean, median etc) are calculated on the features of each cluster to summarise that cluster’s network profile.
    
3.  ml [python script]
    a.   All the csv files containing batches of data are combined into one dataframe.
   b.  Some features are dropped before running the dataframe through the machine learning model.
   c.  `RandomForestClassifier` is used to train the data.
   d.   The trained model is saved using `pickle` in `batch_network_traffic_classifier.sav`
   
## Pipeline for Testing

### ddosdetect [python script]
1.  Features are extracted.
2.  Feature engineering is done.
3. Batches are formed.    
4. Classification of clusters is done.    
5.  The `benign` and `ddos_attack` traffic is outputted in `FINAL_OUTPUT.txt`.

## Coding Conventions
-   `ddosdetect.py` creates the folder `TEMPORARY_FILES` to store temporary `.csv files`, text files which contain the path to pcap files etc
    
-   `feature_extraction.py` creates the folders `CSV_FILES/BENIGN` and `CSV_FILES/MALWARE` to store the data extracted from the `pcap` files using `tshark`
    
-   `feature_engineering.py` creates the folders `CSV_FILES_BATCH`, `CSV_FILES_PATH_LIST`, `PCAP_CSV_FILES` to store temporary files as needed.
    
-   `ml.py` stores the trained Machine Learning model in `batch_network_traffic_classifier.sav`

## Feature Extraction
-   In this work, the goal is to identify characteristics in network traffic that are able to distinguish the normal network behavior from DoS attacks.    
-   For feature extraction we used the command line tool tshark which helps parse pcap files with ease and form CSVs of required fields. We extracted the following 
	- Frame number- Helps mark the specific packets that have been marked as malicious in network traffic.   
	-  Source IP address - Helps monitor the packets that have been sent to and from the host. This is essential in the output file.    
	-  Destination IP address    
	-   Protocol used- Since a large number of DDoS attacks are carried over protocols such as ICMP and UDP. The protocol used is a worthy feature to use in the classifier.    
	- TCP_SourcePort
	- TCP_DestPort    
	- TCP_Flags    
	- UDP_SourcePort    
	- USP_DestPort    
	- UDP_Flags



## Feature Engineering

Summary statistics on some features were calculated to ensure the importance of features is correctly measured.

-   IP Protocol    
-   IP source - Mean, Median, Var, Standard Deviation, Cross Variance, Rate of change    
-   IP Destination - Mean, Median, Var, Standard Deviation, Cross Variance, Rate of change    
-   Source Port - Mean, Median, Var, Standard Deviation, Cross Variance, Rate of change    
-   Destination Port - Mean, Median, Var, Standard Deviation, Cross Variance, Rate of change    
-   TCP Flags - Mean, Median, Var, Standard Deviation, Cross Variance, Rate of change

![Confusion Matrix][/Confusion Matrix.png]
![Feature Importance][/Feature_Importance.png]

