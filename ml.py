import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV
import matplotlib.pyplot as plt
import numpy as np
import pickle
import os
import itertools

def status_to_int(s):
	if (s == 'benign'): return 0
	if (s == 'malware'): return 1

# # combine all benign and malware csv files csv files
# os.system('find ./CSV_FILES_BATCH/ -name "*_benign.csv" > ./CSV_FILES_PATH_LIST/benign_batch_csv_files_list.txt')
# os.system('find ./CSV_FILES_BATCH/ -name "*_malware.csv" > ./CSV_FILES_PATH_LIST/malware_batch_csv_files_list.txt')

# benign_file_list = open('./CSV_FILES_PATH_LIST/benign_batch_csv_files_list.txt').read()
# malware_file_list = open('./CSV_FILES_PATH_LIST/malware_batch_csv_files_list.txt').read()

# benign_file_list = benign_file_list.split('\n')[0:-1]
# malware_file_list = malware_file_list.split('\n')[0:-1]

# # combine all files list
# benign_csv_combined = pd.concat([pd.read_csv(f) for f in benign_file_list ], ignore_index = True)
# malware_csv_combined = pd.concat([pd.read_csv(f) for f in malware_file_list ], ignore_index = True)

# # export to csv
# benign_csv_combined.to_csv( "./CSV_FILES_BATCH/benign.csv", index = False)
# malware_csv_combined.to_csv( "./CSV_FILES_BATCH/malware.csv", index = False)

# read combined dataframes
df_benign = pd.read_csv('./CSV_FILES_BATCH/benign.csv')
df_malware = pd.read_csv('./CSV_FILES_BATCH/malware.csv')

df = [df_benign, df_malware]
df = pd.concat(df, ignore_index = True)

df = df.fillna(0)


df['status'] = df['status'].apply(status_to_int)

X_drop_columns = ['status']

drop = ['ip.src.len.entropy', 'ip.src.len.cvq','ip.dst.len.entropy', 'ip.dst.len.cvq', 'sport.entropy', 'sport.cvq', 'dport.entropy', 'dport.cvq', 'tcp.flags.entropy', 'tcp.flags.cvq',]

X_drop_columns_more = ['ip.src.len.median', 'ip.src.len.var', 'ip.src.len.std','ip.src.len.cv', 'ip.src.len.rte', 'ip.dst.len.median', 'ip.dst.len.var', 'ip.dst.len.std', 'ip.dst.len.cv', 'ip.dst.len.rte','tcp.flags.mean', 'tcp.flags.median', 'tcp.flags.var', 'tcp.flags.std', 'tcp.flags.entropy', 'tcp.flags.cv', 'tcp.flags.cvq', 'tcp.flags.rte']

y_drop_columns = ['ip.proto', 'ip.src.len.mean', 'ip.src.len.median', 'ip.src.len.var', 'ip.src.len.std', 'ip.src.len.entropy', 'ip.src.len.cv', 'ip.src.len.cvq', 'ip.src.len.rte', 'ip.dst.len.mean', 'ip.dst.len.median', 'ip.dst.len.var', 'ip.dst.len.std', 'ip.dst.len.entropy', 'ip.dst.len.cv', 'ip.dst.len.cvq', 'ip.dst.len.rte', 'sport.mean', 'sport.median', 'sport.var', 'sport.std', 'sport.entropy', 'sport.cv', 'sport.cvq', 'sport.rte', 'dport.mean', 'dport.median', 'dport.var', 'dport.std', 'dport.entropy', 'dport.cv', 'dport.cvq', 'dport.rte', 'tcp.flags.mean', 'tcp.flags.median', 'tcp.flags.var', 'tcp.flags.std', 'tcp.flags.entropy', 'tcp.flags.cv', 'tcp.flags.cvq', 'tcp.flags.rte']

X = df.drop(drop + X_drop_columns_more + ['status'], axis = 1).values
y = df.drop(y_drop_columns, axis = 1).values

# # drop 1st column
# X = X[:, 1:]
# y = y[:, 1:]

# convert dtype to int
X = X.astype(float)
y = y.astype(float)

X_train, X_test, y_train, y_test = train_test_split(X, y)

#  == PREPROCESSING ==
scaler = StandardScaler()
scaler.fit(X_train)
X_train_scaled = scaler.transform(X_train)
X_test_scaled = scaler.transform(X_test)

# # == TRAINING ==
forest = RandomForestClassifier(n_estimators=10)
forest.fit(X_train_scaled, y_train.ravel())

# save the model to disk
filename = 'batch_network_traffic_classifier.sav'
pickle.dump(forest, open(filename, 'wb'))

# print("RandomForestClassifier accuracy: {:.2f}".format(forest.score(X_test_scaled, y_test)*100))
y_pred = forest.predict(X_test_scaled)
a = accuracy_score(y_test, y_pred)
p,r,f,s = precision_recall_fscore_support(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
print("RandomForestClassifier")
print(f"accuracy : {a}\nprecision : {p}\nrecall : {r}\nf1 score : {f1}\nflase positive (fall out) : {fp / (fp + tn)}\nfalse negative (miss rate) : {fn / (fn + tp)}")

print("======")

# == PRINT METRICS ==
# 1. Feature Importance
features = df.drop(drop + X_drop_columns_more + ['status'], axis = 1).columns;
importances = forest.feature_importances_

feature_importance = dict()
for feature, importance in zip(features, importances):
	feature_importance[feature] = importance

print(type(feature_importance))

for i in feature_importance.items():
	print(i)

feature_importance_sorted = sorted(feature_importance.items(), key=lambda x: x[1], reverse = True)


plt.barh([i[0] for i in feature_importance_sorted], [i[1] for i in feature_importance_sorted])
plt.xticks(rotation = 75)
plt.xlabel("Features", fontsize = 'large', fontweight = 'demi')
plt.ylabel("Relative Importance", fontsize = 'large', fontweight = 'demi')
plt.title("Feature Importance", fontsize = 'x-large', fontweight = 'bold')
plt.show()

# 2. Confusion Matrix
def plot_confusion_matrix(cm, classes,
                          normalize=False,
                          title='Confusion matrix',
                          cmap=plt.cm.Blues):
    """
    This function prints and plots the confusion matrix.
    Normalization can be applied by setting `normalize=True`.
    """
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)

    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')

    print(cm)

    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, cm[i, j],
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black")

    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.show()

# Compute confusion matrix
cnf_matrix = confusion_matrix(y_test, y_pred)
np.set_printoptions(precision=2)


# Plot normalized confusion matrix
plt.figure()
# Plot non-normalized confusion matrix
plt.figure()
plot_confusion_matrix(cnf_matrix, classes=['Safe Trafic', 'DDoS Traffic'], title='Confusion matrix, without normalization')

# ======================================TESTING===================================================
# batch_network_traffic_classifier = pickle.load(open("./batch_network_traffic_classifier.sav", 'rb'))

# df = pd.read_csv('./Dataset/testdata2/benign/p2pbox1/p2pbox1_batch.csv')

# df = df.fillna(0)

# print(df.columns)

# X = df.drop(['status'], axis = 1).values

# X = X.astype(float)

# scaler = StandardScaler()
# scaler.fit(X)
# X_scaled = scaler.transform(X)

# y_pred = batch_network_traffic_classifier.predict(X_scaled)
# print(f"malware : {sum(y_pred == 1)}")
# print(f"benign : {sum(y_pred == 0)}")

# =================================================================================================
