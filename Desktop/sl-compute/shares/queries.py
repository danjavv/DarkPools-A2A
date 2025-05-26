import json
names = ['frankjuarez', 'meganlong', 'lowewilliam', 'jamesthomas', 'alexis61', 'chandlercarla', 'jacksonbryan', 'janice56', 'jason62', 'avilasandra', 'bbartlett', 'christopherwashington', 'davidatkinson', 'ehardy', 'ubass', 'stevenpark', 'rlynch', 'shawn31', 'alan92', 'catherine08', 'fcarter', 'alexander94', 'michael73', 'aaronmaldonado', 'davidreyes', 'camachoamanda', 'joseklein', 'michaelmyers', 'morristimothy', 'tiffany18', 'emilyblair', 'anthonywalls', 'joshua62', 'coffeymichael', 'anthonylewis', 'nicholasknight', 'carol06', 'amanda58', 'martintara', 'oconnormonica', 'larry56', 'kennedyelaine', 'vhahn', 'whampton', 'abigail93', 'evan30', 'ygarcia', 'evelyn30', 'sallyhuff', 'charlottewyatt', 'suebuchanan', 'lortega', 'jacobrobinson', 'caitlin76', 'fmercer', 'douglascharles', 'andrewmartinez', 'mullenerica', 'teresamartin', 'wmarshall', 'sanderschristina', 'ucook', 'nicole75', 'fredgordon', 'blakedonna', 'william34', 'ogilmore', 'philip72', 'jenningsjohn', 'markramirez', 'huntpaige', 'jon39', 'justin22', 'linda53', 'youngsarah', 'lodom', 'john22', 'leeyvonne', 'oreynolds', 'harrisonalexa', 'rebecca31', 'stevenfrancis', 'sharplisa', 'erikawhite', 'daniel87', 'webercory', 'gainesjeff', 'vmiller', 'acoffey', 'marymcintosh', 'padillajacob', 'dsims', 'emilyestes', 'victoria28', 'patelelijah', 'nhancock', 'michelleanderson', 'rmichael', 'daniel92', 'ythomas', 'rachael71', 'johnathanflores', 'awashington', 'micheal94', 'alex69', 'michaelwong', 'walkercynthia', 'jonathanowens', 'daniel25', 'cvillarreal', 'pmitchell', 'jeff81', 'madeline93', 'jameslogan', 'angelicayoung', 'charlessmith', 'bonillastacy', 'steven86', 'jermaine65', 'carrie86', 'amorris', 'kevinreed', 'joneslisa', 'cynthia38', 'kara17', 'sethphillips', 'robinsondevin', 'debra91', 'hillsandra', 'jacobtaylor', 'wmartinez', 'xfoster', 'brian30', 'zjoyce', 'melody97', 'joseph57', 'ortizann', 'chrisdavis', 'reidraymond', 'emmalarson', 'morgankevin', 'wendy36', 'hhansen', 'fhooper', 'ryansosa', 'traci98', 'debramoore', 'brianbest', 'mccarthymorgan', 'harperkristina', 'clarson', 'brownaaron', 'rodriguezkelly', 'wnelson', 'kaitlynday', 'brian41', 'michael67', 'tammy25', 'heather89', 'allenmatthew', 'lindsay50', 'wongjennifer', 'chandlerkaren', 'wrightkenneth', 'vpierce', 'ttrujillo', 'douglas05', 'garyharper', 'troyjensen', 'raymondlang', 'leedanielle', 'claudia62', 'raymondaguirre', 'zachary33', 'margarethale', 'usantiago', 'ethan08', 'andres11', 'justinlucero', 'timothyshaw', 'leslie23', 'pachecojerry', 'henry38', 'mathewschristine', 'diane77', 'valerieguerrero', 'jacobjones', 'mirandajennifer', 'suarezbobby', 'crawforddwayne', 'micheal46', 'timothybrown', 'smithomar', 'fweaver', 'kjohnson', 'vmedina', 'whitneyvincent', 'troystephens', 'kennedyjonathan', 'mcunningham', 'christinehawkins', 'mgarner', 'jason00', 'joangross', 'burnskelly', 'steven90', 'vneal', 'phillipsstephanie', 'shawn81', 'richardmark', 'frank94', 'shelly18', 'thorntonjoshua', 'amber04', 'sandracortez', 'phillip09', 'christiandeleon', 'bestjennifer', 'hernandezkristi', 'josephshort', 'fthompson', 'pdoyle', 'sroth', 'ibrock', 'rachel04', 'timothy04', 'angel99', 'tammy16', 'danielmaria', 'rhouse', 'roserobert', 'sgonzalez', 'michael75', 'anthony82', 'charris', 'timothyroberson', 'austinpatrick', 'tmcclure', 'manuelholmes', 'carpentercolleen', 'pennyknox', 'john95', 'william83', 'nicolekelley', 'lclark', 'spruitt', 'christine33', 'sharimalone', 'diane94', 'lawrenceanne', 'mreyes', 'ortegakatherine', 'williamkennedy', 'kathleen81', 'james39', 'chadmorgan', 'mariah05', 'howelllarry', 'luceropeter', 'hendersonjohn', 'bensonjacqueline', 'tannermartinez', 'cherylhoward', 'marilynphillips', 'qdavies', 'moranbrittany', 'wesleydavidson', 'aking', 'mark16', 'ncole', 'laurabaxter', 'mary11', 'john57', 'jessewilliams', 'kennethparker', 'herringjessica', 'whitneywilliams', 'crawfordadriana', 'thomasmontoya', 'benjamincervantes', 'tammy41', 'julia88', 'rachel42', 'jacobselizabeth', 'lsmith', 'jonesscott', 'rachelscott', 'hallmichael', 'brownsue', 'greenjennifer', 'millermarissa', 'colemanjasmine', 'jacqueline07', 'nancy65', 'terry75', 'stephen42', 'jerry39', 'btucker', 'fisherheather', 'yrodriguez', 'albertsanders']


def query1():
    month = 8
    year = 2005
    x = 4
    daterange = {}
    for i in range(x+1):
        daterange[(month-i, year)] = [0,0]

    with open("join_roh_bank.json", "r") as table_file:
        table = json.load(table_file)
        for entry in table:
            dat, year = int(entry["Order Date"].split('-')[1]), int(entry["Order Date"].split('-')[0])
            if year == 2005 and dat >=4 and dat <= 8:
                daterange[(dat, year)][0] += float(entry["Shipment Item Subtotal"])
                daterange[(dat, year)][1] += 1
    
    print(daterange)
    for x in daterange:
        print(x, daterange[x][0]/daterange[x][1])

def query5():

    totalpur = {}
    with open("join_roh_users.json", "r") as table_file:
        table = json.load(table_file)
        for entry in table:
            dat, year = int(entry["Order Date"].split('-')[1]), int(entry["Order Date"].split('-')[0])
            if year == 2005 and dat <= 8 and entry["Order Status"] == "Closed":
                user = entry["user_name"]
                if user not in totalpur:
                    totalpur[user] = 1
                else:
                    totalpur[user] += 1
    print(totalpur)
    
    totalret = {}
    with open("join_roh_return.json", "r") as table_file:
        table = json.load(table_file)
        for entry in table:
            dat, year = int(entry["Order Date"].split('-')[1]), int(entry["Order Date"].split('-')[0])
            if year == 2005 and dat >= 6 and dat <= 8 :
                user = entry["user_name"]
                if user not in totalret:
                    totalret[user] = 1
                else:
                    totalret[user] += 1
    print(totalret)

def query4():
    amthreshold = 200
    credthreshold = 200
    usercount = 0
    with open("join_roh_bank.json", "r") as table_file:
        table = json.load(table_file)
        for user in names:
            credcount = 0
            credtotal = 0
            amcount = 0
            amtotal = 0
            for entry in table:
                dat, year = int(entry["Order Date"].split('-')[1]), int(entry["Order Date"].split('-')[0])
                if user == entry["user_name"] and year == 2005 and dat == 8:
                    credtotal += float(entry["credit"])
                    credcount += 1
                    if entry["website"] == "Amazon.com":
                        amtotal += float(entry["Shipment Item Subtotal"])
                        amcount += 1
            if amcount > 0 and credcount > 0 and amtotal/amcount >= amthreshold and credtotal/credcount >= credthreshold:
                print(user, credcount, credtotal, amcount, amtotal)
                usercount += 1
    print(usercount)

def query3():

    with open("join_roh_users.json", "r") as user_file:
        usertable = json.load(user_file)
        for user in names:
            maxshipadd = None
            maxshipaddcount = 0
            bankadd = None
            for entry in usertable:
                if user == entry["user_name"]:
                    shipadd = entry["Shipping Address"]
                    count = 0
                    for entry2 in usertable:
                        if user == entry2["user_name"] and shipadd == entry2["Shipping Address"]:
                            count += 1
                    if count > maxshipaddcount:
                        maxshipaddcount = count
                        maxshipadd = entry2["Shipping Address"]
                    bankadd = entry2["user_account_holder_information"]["address"]
            print(user, "\nmaxshipadd", maxshipadd, "\nmaxshipaddcount", maxshipaddcount, "\nbankadd", bankadd, "\n\n\n\n")




# query3()

query5()
# and entry["ReturnReason"] == "Refused"