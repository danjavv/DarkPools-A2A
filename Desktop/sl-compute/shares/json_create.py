import json
import random
import string
import uuid
from faker import Faker
from datetime import datetime, timedelta

FIELD_POWER = 64
DECIMAL_PRECISION = 10

names = ['frankjuarez', 'meganlong', 'lowewilliam']

def create_retail_order_history():
    # Initialize Faker for generating random data
    fake = Faker()

    # Number of random entries you want in the JSON file
    num_entries = 250

    # Helper function to generate random strings and numbers
    def random_string(length):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

    def random_varying():
        return random_string(random.randint(5, 15))

    def random_integer(min_value, max_value):
        return random.randint(min_value, max_value)

    def random_currency():
        currencies = ["USD", "EUR", "GBP", "INR", "JPY"]
        return random.choice(currencies)

    # Generate random data for each entry
    data = []
    for _ in range(num_entries):
        entry = {
            "website": random.choice(["Amazon.com", "eBay.com", "Walmart.com", "AliExpress.com", "Etsy.com", "Target.com", "BestBuy.com", "Rakuten.com", "Shopify.com", "Myntra.com", "Zappos.com", "Newegg.com", "Overstock.com", "Wayfair.com", "Snapdeal.com", "JD.com"]),
            "Order ID": random_string(10),
            "Order Date": fake.date(),
            "Purchase Order Number": random_string(12),
            "currency": random_currency(),
            "Unit Price": f"{random.uniform(5.0, 100.0):.2f}",
            "Unit Price Tax": f"{random.uniform(0.5, 10.0):.2f}",
            "Shipping Charge": str(random_integer(5, 50)),
            "Total Discounts": f"{random.uniform(1.0, 20.0):.2f}",
            "Total Owed": f"{random.uniform(50.0, 500.0):.2f}",
            "Shipment Item Subtotal": f"{random.uniform(50.0, 400.0):.2f}",
            "Shipment Item Subtotal Tax": f"{random.uniform(2.0, 20.0):.2f}",
            "asin": str(random_string(10)),
            "Product Condition": random.choice(["New", "Used", "Refurbished"]),
            "quantity": str(random_integer(1, 10)),
            "Payment Instrument Type": random.choice(["Credit Card", "Debit Card", "PayPal", "Gift Card"]),
            "Order Status": random.choice(["Pending", "Closed", "Cancelled"]),
            "Shipment Status": random.choice(["Shipped", "In Transit", "Delivered", "Awaiting Shipment"]),
            "Ship Date": fake.date(),
            "Shipping Option": random.choice(["Standard", "Express", "Same Day"]),
            "Shipping Address": fake.address(),
            "Billing Address": fake.address(),
            "Carrier Name & Tracking Number": f"{random.choice(['UPS', 'FedEx', 'DHL'])}, {random_string(12)}",
            "Product Name": fake.word(),
            "Gift Message": random.choice([fake.sentence(), ""]),
            "Gift Sender Name": fake.name(),
            "Gift Recipient Contact Details": fake.phone_number(),
            "user_name": random.choice(names)
        }
        data.append(entry)

    # Write data to a JSON file
    with open("retail_order_history.json", "w") as json_file:
        json.dump(data, json_file, indent=4)

    print("JSON file with random entries generated successfully.")

def create_users_table():
    fake = Faker()

    # Create a new list for the users table with the same user_name entries
    users_data = []

    for name in names:
        user_entry = {
            "uuid": str(uuid.uuid4()),
            "user_name": name,
            "user_account_holder_information": {
                "name": fake.name(),
                "email": fake.email(),
                "address": fake.address(),
                "phone_number": fake.phone_number()
            },
            "created_at": datetime.now().isoformat()
        }
        users_data.append(user_entry)

    print(len(users_data))

    # Write the users data to a JSON file
    with open("users_table.json", "w") as json_file:
        json.dump(users_data, json_file, indent=4)

    print("Users table with the same user names generated successfully.")

def create_bank_statement_consolidated_table(retail_order_transactions_data):
    fake = Faker()

    def random_category():
        return random.choice(["Shopping", "Groceries", "Utilities", "Entertainment", "Healthcare", "Travel"])

    def random_transaction_amount():
        return str(round(random.uniform(10.0, 1000.0), 2))
    
    def random_subcategory(category):
        subcategories = {
            "Shopping": ["Electronics", "Clothing", "Household"],
            "Groceries": ["Supermarket", "Local Market", "Online Grocery"],
            "Utilities": ["Electricity", "Water", "Gas", "Internet"],
            "Entertainment": ["Movies", "Music", "Games"],
            "Healthcare": ["Pharmacy", "Doctor", "Hospital"],
            "Travel": ["Flights", "Hotels", "Car Rental", "Fuel"]
        }
        return random.choice(subcategories.get(category, []))
    
    def get_random_transaction(user):
        transaction_date = fake.date_between(start_date='-1y', end_date='today')
        transaction_category = random_category()
        transaction_entry = {
            "date": transaction_date.isoformat(),
            "tran_id": fake.uuid4(),
            "transaction_details": fake.sentence(),
            "utr_number": fake.uuid4(),
            "instr_id": str(random.randint(100000, 999999)),
            "debit": random_transaction_amount(),
            "credit": random_transaction_amount(),
            "balance": random_transaction_amount(),
            "transaction_category": transaction_category,
            "transaction_subcategory": random_subcategory(transaction_category),
            "source": user,
            "transaction_reference_no": fake.uuid4(),
            "date_of_transaction_completion": (transaction_date + timedelta(days=random.randint(1, 5))).isoformat()
        }
        return transaction_entry

    def get_retail_order_transaction(retail_order):
        if retail_order["Order Status"] == "Cancelled":
            debit_amt = str(0)
            credit_amt = retail_order["Total Owed"]
        else:
            credit_amt = str(0)
            debit_amt = retail_order["Total Owed"]

        transaction_category = random_category()
        transaction_entry = {
            "date": retail_order["Order Date"],
            "tran_id": fake.uuid4(),
            "transaction_details": fake.sentence(),
            "utr_number": fake.uuid4(),
            "instr_id": str(random.randint(100000, 999999)),
            "debit": debit_amt,
            "credit": credit_amt,
            "balance": random_transaction_amount(),
            "transaction_category": transaction_category,
            "transaction_subcategory": random_subcategory(transaction_category),
            "source": retail_order["user_name"],
            "transaction_reference_no": retail_order["Order ID"],
            "date_of_transaction_completion": (datetime.fromisoformat(retail_order["Order Date"]) + timedelta(days=random.randint(1, 5))).isoformat()
        }
        return transaction_entry
    
    bank_statements = []

    for order in retail_order_transactions_data:
        bank_statements.append(get_retail_order_transaction(order))
    
    for name in names:
        for i in range(8):
            bank_statements.append(get_random_transaction(name))

    # Write the users data to a JSON file
    with open("bank_statement_consolidated.json", "w") as json_file:
        json.dump(bank_statements, json_file, indent=4)

    print("bank_statement_consolidated table generated successfully.")

def create_retail_customerreturns_table(retail_order_transactions_data):
    fake = Faker()
    def random_return_reason():
        return random.choice([
            "Damaged Item", "Wrong Item", "Item Not as Described", 
            "Product Defective", "Refused"
        ])

    def random_resolution():
        return random.choice([
            "Refunded", "Replacement Sent", "Return Denied", "Awaiting Pickup"
        ])

    def random_currency():
        return random.choice(["USD", "EUR", "INR", "GBP", "JPY"])
    
    customer_returns_data = []

    for name in names:
        count = 0
        for order in retail_order_transactions_data:
            if order["user_name"] == name and order["Order Status"] == "Closed" and count < 3 and int(fake.credit_card_number()[0]) % 2 == 0:
                return_entry = {
                    "OrderId": order["Order ID"],
                    "ContractId": fake.uuid4(),
                    "DateOfReturn": fake.date_this_year().isoformat(),
                    "ReturnAmount": str(round(random.uniform(10.0, 500.0), 2)),
                    "ReturnAmountCurrency": random_currency(),
                    "ReturnReason": random_return_reason(),
                    "Resolution": random_resolution(),
                    "Return Authorization Id": fake.uuid4(),
                    "Tracking Id": fake.uuid4(),
                    "RMA Creation Date": fake.date_this_year().isoformat(),
                    "Return Ship Option": fake.word(),
                    "Carrier Package Id": fake.uuid4()
                }
                customer_returns_data.append(return_entry)
                count += 1

    with open("retail_customerreturns.json", "w") as json_file:
        json.dump(customer_returns_data, json_file, indent=4)

    print("Random data for retail_customerreturns table generated successfully.")

def join_retail_hist_user(ret_data, user_data):
    entries = []
    for x in ret_data:
        for y in user_data:
            if x["user_name"] == y["user_name"]:
                joined_entry = {**x, **y}
                entries.append(joined_entry)

    # Write the joined data to a new JSON file
    with open("join_roh_users.json", "w") as output_file:
        json.dump(entries, output_file, indent=4)

    print("Join between retail_order_history and users table completed successfully.")

def join_retail_hist_bank_stat(ret_data, bank_data):
    entries = []
    for x in ret_data:
        for y in bank_data:
            if y["transaction_reference_no"] == x["Order ID"] and y["source"] == x["user_name"] and y["date"] == x["Order Date"]:
                joined_entry = {**x, **y}
                entries.append(joined_entry)

    # Write the joined data to a new JSON file
    with open("join_roh_bank.json", "w") as output_file:
        json.dump(entries, output_file, indent=4)

    print("Join between retail_order_history and bank_statement_consolidated table completed successfully.")
    
def join_retail_hist_cust_ret(rethist_data, custret_Data):
    entries = []
    for x in rethist_data:
        for y in custret_Data:
            if y["OrderId"] == x["Order ID"]:
                joined_entry = {**x, **y}
                entries.append(joined_entry)

    # Write the joined data to a new JSON file
    with open("join_roh_return.json", "w") as output_file:
        json.dump(entries, output_file, indent=4)

    print("Join between retail_order_history and retail_customerreturns table completed successfully.")

arithmeticsharecolumns = ["debit", "credit", "balance", "Unit Price", "Unit Price Tax", "Shipping Charge", "Total Discounts", "Total Owed", 
                          "Shipment Item Subtotal", "Shipment Item Subtotal Tax", "quantity", "ReturnAmount", ]
datecolumms = ["user_name", "DateOfReturn", "RMA Creation Date", "Order Date", "Ship Date", "created_at", "date", "date_of_transaction_completion"]


def get_bts(string):
    return list(string.encode('iso-8859-1'))

def get_string(bts):
    return ''.join(f'{byte:02x}' for byte in bts)

def get_random_bytes(n):
    random_byte_list = [random.randint(0, 255) for _ in range(n)]
    random_bytes = bytes(random_byte_list)
    return list(random_bytes)

def get_bool_shares(string):
    bts = get_bts(string)
    n = len(bts)
    if n == 0:
        return {
            "s1": "00",
            "s2": "00",
            "s3": "00",
            "t1": "00",
            "t2": "00",
            "t3": "00",
            }
    s1 = get_random_bytes(n)
    s2 = get_random_bytes(n)
    s3 = []
    t1 = []
    t2 = []
    t3 = []
    for i in range(n):
        s3.append(s1[i] ^ s2[i] ^ bts[i])
    for i in range(n):
        t1.append(s1[i] ^ s3[i])
        t2.append(s1[i] ^ s2[i])
        t3.append(s2[i] ^ s3[i])
    return {
        "s1": get_string(s1),
        "s2": get_string(s2),
        "s3": get_string(s3),
        "t1": get_string(t1),
        "t2": get_string(t2),
        "t3": get_string(t3),
        }

def get_arith_string(num):
    hexstring = hex(num)[2:]
    if len(hexstring) > 16:
        print("Value too large")
        return None
    hex_string = hexstring.zfill(16)
    # print(len(hex_string))
    return hex_string

def get_arith_shares(string):
    num = int(float(string) * 2**DECIMAL_PRECISION)
    s1 = random.randint(0, 2**FIELD_POWER)
    s2 = random.randint(0, 2**FIELD_POWER)
    s3 = (num - (s1 + s2))%2**FIELD_POWER
    t1 = (s1 + s3)%2**FIELD_POWER
    t2 = (s1 + s2)%2**FIELD_POWER
    t3 = (s2 + s3)%2**FIELD_POWER
    return {
        "s1": get_arith_string(s1),
        "s2": get_arith_string(s2),
        "s3": get_arith_string(s3),
        "t1": get_arith_string(t1),
        "t2": get_arith_string(t2),
        "t3": get_arith_string(t3),
        }


def get_table_shares(table, table_name):
    p1_share_entries = []
    p2_share_entries = []
    p3_share_entries = []
    for entry in table:
        p1_entries = {}
        p2_entries = {}
        p3_entries = {}
        for column in entry:
            if column in arithmeticsharecolumns:
                shares = get_arith_shares(entry[column])
                p1_entries[column] = f"{shares["t1"]} {shares["s1"]}"
                p2_entries[column] = f"{shares["t2"]} {shares["s2"]}"
                p3_entries[column] = f"{shares["t3"]} {shares["s3"]}"
            elif column in datecolumms:
                p1_entries[column] = f"{entry[column]}"
                p2_entries[column] = f"{entry[column]}"
                p3_entries[column] = f"{entry[column]}"
            else:
                if isinstance(entry[column], str):
                    shares = get_bool_shares(entry[column])
                    p1_entries[column] = f"{shares["t1"]} {shares["s1"]}"
                    p2_entries[column] = f"{shares["t2"]} {shares["s2"]}"
                    p3_entries[column] = f"{shares["t3"]} {shares["s3"]}"
                else: 
                    if isinstance(entry[column], dict):
                        p1_sub_entries = {}
                        p2_sub_entries = {}
                        p3_sub_entries = {}
                        for subcolumn in entry[column]:
                            if subcolumn in datecolumms:
                                p1_entries[column] = f"{entry[column]}"
                                p2_entries[column] = f"{entry[column]}"
                                p3_entries[column] = f"{entry[column]}"
                            shares = get_bool_shares(entry[column][subcolumn])
                            p1_sub_entries[subcolumn] = f"{shares["t1"]} {shares["s1"]}"
                            p2_sub_entries[subcolumn] = f"{shares["t2"]} {shares["s2"]}"
                            p3_sub_entries[subcolumn] = f"{shares["t3"]} {shares["s3"]}"
                        p1_entries[column] = p1_sub_entries
                        p2_entries[column] = p2_sub_entries
                        p3_entries[column] = p3_sub_entries
        p1_share_entries.append(p1_entries)
        p2_share_entries.append(p2_entries)
        p3_share_entries.append(p3_entries)
    
    with open(f"p1_shares/{table_name}_p1.json", "w") as output_file:
        json.dump(p1_share_entries, output_file, indent=4)
    with open(f"p2_shares/{table_name}_p2.json", "w") as output_file:
        json.dump(p2_share_entries, output_file, indent=4)
    with open(f"p3_shares/{table_name}_p3.json", "w") as output_file:
        json.dump(p3_share_entries, output_file, indent=4)

    pass


if __name__ == "__main__":
    # Step 1: Crete the retail_order_history table
    create_retail_order_history()

    # Step 2: Create the users table
    create_users_table()

    # Step 3: Using the created retail_order_history table, create the bank_statement_consolidated and retail_customerreturns tables
    with open("retail_order_history.json", "r") as json_file:
        retail_orders = json.load(json_file)
        create_bank_statement_consolidated_table(retail_orders)
        create_retail_customerreturns_table(retail_orders)

    # Step 4: Create a join between retail_order_history table and users table: join_roh_users table
    with open("retail_order_history.json", "r") as roh_file:
        with open("users_table.json", "r") as users_file:
            retail_orders = json.load(roh_file)
            user_info = json.load(users_file)
            join_retail_hist_user(retail_orders, user_info)

    # Step 5: Create a join between retail_order_history table and bank_statement_consolidated table
    with open("retail_order_history.json", "r") as roh_file:
        with open("bank_statement_consolidated.json", "r") as bank_file:
            retail_orders = json.load(roh_file)
            bank_stat = json.load(bank_file)
            join_retail_hist_bank_stat(retail_orders, bank_stat)
    

    # Step 6: Create a join between retail_order_history table and retail_customerreturns table
    with open("retail_order_history.json", "r") as roh_file:
        with open("retail_customerreturns.json", "r") as bank_file:
            retail_orders = json.load(roh_file)
            cust_ret = json.load(bank_file)
            join_retail_hist_cust_ret(retail_orders, cust_ret)

    # Step 7: Get shares of join_roh_users table
    with open("join_roh_users.json", "r") as table_file:
        table = json.load(table_file)
        get_table_shares(table, "join_roh_users")

        
    # Step 8: Get shares of join_roh_bank table
    with open("join_roh_bank.json", "r") as table_file:
        table = json.load(table_file)
        get_table_shares(table, "join_roh_bank")

        
    # Step 9: Get shares of join_roh_return table
    with open("join_roh_return.json", "r") as table_file:
        table = json.load(table_file)
        get_table_shares(table, "join_roh_return")
    pass