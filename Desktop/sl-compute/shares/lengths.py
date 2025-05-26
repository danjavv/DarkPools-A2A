import json
import math

uniquelengths = {}

table_name = "join_roh_users"
with open(f"p1_shares/{table_name}_p1.json", "r") as json_file:
    entries = json.load(json_file)
    for column in entries[0]:
        uniquelengths[column] = 0
    for column in entries[0]["user_account_holder_information"]:
        uniquelengths[column] = 0
    for entry in entries:
        for column in entry:
            uniquelengths[column] = max(uniquelengths[column], (len(entry[column])-1)/2)
        for column in entry["user_account_holder_information"]:
            uniquelengths[column] = max(uniquelengths[column], (len(entry["user_account_holder_information"][column])-1)/2)

table_name = "join_roh_return"
with open(f"p1_shares/{table_name}_p1.json", "r") as json_file:
    entries = json.load(json_file)
    for column in entries[0]:
        if column not in uniquelengths:
            uniquelengths[column] = 0
    for entry in entries:
        for column in entry:
            uniquelengths[column] = max(uniquelengths[column], (len(entry[column])-1)/2)

table_name = "join_roh_bank"
with open(f"p1_shares/{table_name}_p1.json", "r") as json_file:
    entries = json.load(json_file)
    for column in entries[0]:
        if column not in uniquelengths:
            uniquelengths[column] = 0
    for entry in entries:
        for column in entry:
            uniquelengths[column] = max(uniquelengths[column], (len(entry[column])-1)/2)

# print(uniquelengths)

uniquelengths2 = uniquelengths.copy()

for col in uniquelengths:
    uniquelengths2[col] = math.ceil(uniquelengths[col]/16)

# for col in uniquelengths:
#     print(uniquelengths2[col]*16 >= uniquelengths[col], (uniquelengths2[col]-1)*16 < uniquelengths[col])

print("\n\n", uniquelengths2, sum(list(uniquelengths2.values())))

# print("[")
# for col in uniquelengths2:
#     print(f"    (\"{col}\", {uniquelengths2[col]}usize)")
# print("]")

table_name = "join_roh_users"
with open(f"p1_shares/{table_name}_p1.json", "r") as json_file:
    entries = json.load(json_file)
    sumv = 0
    for column in entries[0]:
        sumv += uniquelengths2[column]
    print(sumv, table_name)
    
table_name = "join_roh_return"
with open(f"p1_shares/{table_name}_p1.json", "r") as json_file:
    entries = json.load(json_file)
    sumv = 0
    for column in entries[0]:
        sumv += uniquelengths2[column]
    print(sumv, table_name)
    
table_name = "join_roh_bank"
with open(f"p1_shares/{table_name}_p1.json", "r") as json_file:
    entries = json.load(json_file)
    sumv = 0
    for column in entries[0]:
        sumv += uniquelengths2[column]
    print(sumv, table_name)


def get_uniquelengths():
    return uniquelengths2