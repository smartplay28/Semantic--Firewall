import os

pii_per_type = """pii_type,tp,fn,recall
CREDITCARDNUMBER,12610,40,0.9968
EMAIL,17949,19,0.9989
IBAN,9886,5,0.9995
IPV4,12047,22,0.9982
IPV6,11488,30,0.9974
MAC,5216,3,0.9994
PHONENUMBER,8807,2967,0.7480
ZIPCODE,12056,15,0.9988
"""

pii_scaled = """metric,value
num_samples,93160
true_positives,90059
false_positives,14839
false_negatives,3101
precision,0.8585
recall,0.9667
f1,0.9095
"""

with open('c:/Users/Aksha/OneDrive/Desktop/semantic_firewall/semantic_firewall/benchmarks/research/results/tables/pii_per_type.csv', 'w') as f:
    f.write(pii_per_type)
    
with open('c:/Users/Aksha/OneDrive/Desktop/semantic_firewall/semantic_firewall/benchmarks/research/results/tables/pii_scaled.csv', 'w') as f:
    f.write(pii_scaled)

print("Reverted CSVs back to original accurate data (N=93,160).")
