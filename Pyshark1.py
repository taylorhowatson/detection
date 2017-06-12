import urllib2
import urllib
import multiprocessing
import Queue
import pyshark
import sqlite3

def read_the_channel():
#general inport channel. had some troubles with it so ported back to main func area
    interface1 = pyshark.LiveCapture(interface="en0", bpf_filter='broadcast')
    interface1.sniff(timeout=50)

    #return interface1
    return

def database_init():

    #we need to be clearing these databases when we start-up/run through this init process. 

    conn = sqlite3.connect('device_info.db')
    c = conn.cursor()


    # Create table
    #c.execute('''CREATE TABLE Signal_Info(time, mac_address, singal_strength)''')
   
   
    c.execute('''CREATE TABLE Devices_Known(mac_address, table_address)''')

    #we need to look at a table and see if we know the device by the mac address. 
   

    # Insert a row of data
   # c.execute("INSERT INTO Signal_Info VALUES ('0','','')")

    # Save (commit) the changes
    conn.commit()

    # We can also close the connection if we are done with it.
    # Just be sure any changes have been committed or they will be lost.
    conn.close()


    return 

def signal_tracking(mac_address, strength, time_stamp):
    flag = 0
    conn = sqlite3.connect('device_info.db')
    c = conn.cursor()
    c.execute('''SELECT mac_address, table_address FROM Devices_Known''')
    #aim is to add signal stregth table, hence the individual table)_address. 
    
    all_rows = c.fetchall()
    for row in c:
        #iterate and search for Mac Address
        if (row[0] == mac_address):
            #Save the signal strenth data to a table which has been build for that device
            tablename = row[1] #get the table name for that device
            flag = 1
            #conn.execute("INSERT into tablename VALUES (?, ?, ?)", (time_stamp, mac_address, strength))
    if (flag == 0):
        #we have a new device, and therefore need to make a new table for signal strength
        table_name = "something" #New table name, need to individualise this
        conn.execute("INSERT into Devices_Known VALUES (?, ?)", (mac_address, table_name))
        #need to look up the table
    conn.execute("INSERT into Signal_Info VALUES (?, ?, ?)", (time_stamp, mac_address, strength))
    conn.commit()
    conn.close()

    #insert the timestamped data into the data
    # base.
    return counter, array

#Iterate across the captured data.

def read_the_data(mac_address, counter, array):
    flag = 0
    #Funciton that keeps a list of devices around it in SQLite. 
    conn = sqlite3.connect('device_info.db')
    c = conn.cursor()
    c.execute('''SELECT * FROM Devices_Known''')
    rows = c.fetchall()
     #aim is to add signal stregth table, hence the individual table)_address.
    for i in rows:
        #iterate and search for Mac Address
        if (i[0] == mac_address):
            #Save the signal strenth data to a table which has been build for that device
            #tablename = row[1] #get the table name for that device
            #conn.commit()
            flag = 1
            #conn.execute("INSERT into tablename VALUES (?, ?, ?)", (time_stamp, mac_address, strength))
    if (flag == 0):
        #we have a new device, and therefore need to make a new table for signal strength
        vendor_lookup(mac_address[0:8].upper())
        
        print mac_address[0:8]
        
        table_name = "something" #New table name, need to individualise this
        conn.execute("INSERT into Devices_Known VALUES (?, ?)", (mac_address, table_name))
        counter += 1        #need to look up the table
   #conn.execute("INSERT into Signal_Info VALUES (?, ?, ?)", (time_stamp, mac_address, strength))
    conn.commit()
    conn.close()

    return counter

def internet_on():
    try:
        urllib2.urlopen('http://216.58.192.142', timeout=1)
        return True
    except urllib2.URLError as err: 
        return False

def vendor_lookup(unique_address):
    #Shopuld use a dictionary or look up taboe here. May need to
    # interface with a file, which holds all these MAC address.
    flag = 0
    with open('Lookup.rtf', 'r') as inF:
        for line in inF:
            if unique_address in line:
                print line
                flag = 1
                return "building functionality"
    
    if (flag == 0):
        print unique_address + " no info found"
        return "no vendor infomation"
        

counter = 0
array = []
database_init()
while (1):
    #interface = pyshark.LiveCapture(interface="en0", bpf_filter='broadcast', capture_filter = 'IEEE802_11_RADIO_AVS', monitor_mode=True)
    interface = pyshark.LiveCapture(interface="en0", bpf_filter='broadcast')
    interface.sniff(timeout=30)
    for packet in interface.sniff_continuously(packet_count=100):
        mac_address = packet.eth.src
        if packet:
            counter = read_the_data(mac_address, counter, array)
            #print packet.eth.src #when not in monitoring mode this is the MAC address. 
        else:
            print "no data found"
   
    print  "%s unique devices in the area" %(counter)



