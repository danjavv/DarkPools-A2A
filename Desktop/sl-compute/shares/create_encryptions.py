import json
from bitarray import bitarray
from bitarray.util import *
from lengths import get_uniquelengths
from aeswithoutMPC import AES

FIELD_POWER = 64
DECIMAL_PRECISION = 10
ENCRYPTION_KEY = bitarray("0"*128)

collengths = get_uniquelengths()
arithmeticsharecolumns = ["debit", "credit", "balance", "Unit Price", "Unit Price Tax", "Shipping Charge", "Total Discounts", "Total Owed", 
                          "Shipment Item Subtotal", "Shipment Item Subtotal Tax", "quantity", "ReturnAmount", ]
datecolumms = ["user_name", "DateOfReturn", "RMA Creation Date", "Order Date", "Ship Date", "created_at", "date", "date_of_transaction_completion"]


def get_bts(string):
    return list(string.encode('iso-8859-1'))

def get_string(bts):
    return ''.join(f'{byte:02x}' for byte in bts)

def get_bool_encryptions(column, string, aes: AES):
    n_ideal = collengths[column]*16
    if len(string) < n_ideal:
        string = string + '\0'*(n_ideal - len(string))
    outstring = ""
    for i in range(collengths[column]):
        toencbts = get_bts(string[16*i: 16*(i+1)])
        hexbts = get_string(toencbts)
        toenc = hex2ba(hexbts)
        encrypted = aes.circuit(key=ENCRYPTION_KEY.copy(), message=toenc)
        outstring += str(ba2hex(encrypted))
    return outstring

def get_arith_encryptions(column, string, aes: AES):
    string = str(int(float(string) * 2**DECIMAL_PRECISION))
    n_ideal = collengths[column]*16
    if len(string) < n_ideal:
        string = '0'*(n_ideal - len(string)) + string
    bts = get_bts(string)
    hexbts = get_string(bts)
    toenc = hex2ba(hexbts)
    encrypted = aes.circuit(ENCRYPTION_KEY.copy(), toenc)
    return ba2hex(encrypted)

def get_table_encryptions(table, table_name):
    table_entries = []
    aes = AES()
    for entry in table:
        entries = {}
        for column in entry:
            if column in arithmeticsharecolumns:
                encryption = get_arith_encryptions(column, entry[column], aes)
                entries[column] = f"{encryption}"
            elif column in datecolumms:
                entries[column] = f"{entry[column]}"
            else:
                if isinstance(entry[column], str):
                    encryption = get_bool_encryptions(column, entry[column], aes)
                    entries[column] = f"{encryption}"
                else:
                    if isinstance(entry[column], dict):
                        sub_entries = {}
                        for subcolumn in entry[column]:
                            if subcolumn in datecolumms:
                                sub_entries[subcolumn] = f"{entry[column][subcolumn]}"
                            else:
                                encryption = get_bool_encryptions(subcolumn, entry[column][subcolumn], aes)
                                sub_entries[subcolumn] = f"{encryption}"
                        entries[column] = sub_entries
        table_entries.append(entries)
    with open(f"{table_name}_encrypted.json", "w") as output_file:
        json.dump(table_entries, output_file, indent=4)

if __name__ == "__main__":
    with open("join_roh_users.json", "r") as table_file:
        table = json.load(table_file)
        get_table_encryptions(table, "join_roh_users")

    with open("join_roh_bank.json", "r") as table_file:
        table = json.load(table_file)
        get_table_encryptions(table, "join_roh_bank")

    with open("join_roh_return.json", "r") as table_file:
        table = json.load(table_file)
        get_table_encryptions(table, "join_roh_return")