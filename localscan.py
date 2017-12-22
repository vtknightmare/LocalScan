from scapy.all import *
import os
import sys
from netaddr import *
import threading
import psycopg2
import signal
import multiprocessing
from tabulate import tabulate
from geoip import geolite2

cur = None
conn = None
is_sending_done = False
active_users = {}
process_collect = None
file_path = {}
users_ip_adresses = []

def connect():
    global conn
    global cur
    try:
        print "[+] Connecting to PostgreSQL database please wait..."
        conn = psycopg2.connect(host="localhost", database="localscan", user="postgres", password="postgres")
        cur = conn.cursor()
        cur.execute('''SELECT * FROM start_occur()''')
        cur.execute('''DELETE FROM logs''')
        cur.execute('''DELETE FROM users''')
        conn.commit()
        print "[-] All data has been removed from users database"
    except (Exception, psycopg2.DatabaseError) as error:
        print "[-] " + str(error)

def add_active_users_to_database(active_users, number_of_users=None):
    
    global is_sending_done
    print "[+] Adding users to database process started, please wait..."
    insert_users = '''INSERT INTO users(ip_adress, mac_adress) VALUES(%s, %s)'''
    for key, value in active_users.iteritems():
         cur.execute(insert_users, (value, key))
    print "[+] Users were added to database..."
    conn.commit()
    active_users.clear()
    is_sending_done = True
def collect_broadcast_data():
    ether_frame = Ether()
    global file_path
    try:
        print "[+] Connecting to PostgreSQL database for collect broadcast data please wait..."
        if os.path.exists(r"./Datas"):
            for root, dirs, files in os.walk("./Datas", topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            print "[-] All datas removed from local disc"
        conn = psycopg2.connect(host="localhost", database="localscan", user="postgres", password="postgres")
        cur = conn.cursor()
        cur.execute('''DELETE FROM broadcasts''')
        conn.commit()
        insert_data = """INSERT INTO broadcasts(sender_ip, sender_mac, data) VALUES(%s, %s, %s)"""
        print "[-] All data has been removed from broadcast database"
        while True: 
            pkt = sniff(filter="ether dst not %s and ether src not %s" % (ether_frame.src, ether_frame.src), count=1) 
            if pkt[0][Ether].type == 2048:
                if not os.path.exists(r"./Datas/data_of_%s" % (pkt[0][IP].src)):
                    file_path[pkt[0][IP].src] = open(r"./Datas/data_of_%s" % (pkt[0][IP].src), "w", 0)
                    insert_data = """INSERT INTO broadcasts(sender_ip, sender_mac, data) VALUES(%s, %s, %s)"""
                    cur.execute(insert_data, (pkt[0][IP].src, pkt[0][Ether].src, "./Datas/data_of_%s" % (pkt[0][IP].src)))
                    conn.commit()
                else:
                    file_path[pkt[0][IP].src].write(pkt[0].summary() + "\n")

            elif pkt[0][Ether].type == 2054:
                if not os.path.exists(r"./Datas/data_of_%s" % (pkt[0][ARP].psrc)):
                    file_path[pkt[0][ARP].psrc] = open(r"./Datas/data_of_%s" % (pkt[0][ARP].psrc), "w", 0)
                    insert_data = """INSERT INTO broadcasts(sender_ip, sender_mac, data) VALUES(%s, %s, %s)"""
                    cur.execute(insert_data, (pkt[0][ARP].psrc, pkt[0][ARP].hwsrc, "./Datas/data_of_%s" % (pkt[0][ARP].psrc)))
                    conn.commit()
                else:
                    file_path[pkt[0][ARP].psrc].write(pkt[0].summary() + "\n")
            
            else:
                pass
            
    except (Exception, psycopg2.DatabaseError) as error:
        print "[-] " + str(error)

def sniff_packets(router_ip, number_of_users):
    global active_users
    global users_ip_adresses
    ether_frame = Ether()
    router_pkt = srp1(Ether()/ARP(pdst=router_ip), verbose=False)
    print "[+] This is your router mac adress that localscan found: " + "\033[91m " + router_pkt[ARP].hwsrc + "\033[0m"
    print "[+] Finding active users process have started. Please wait..."
    while is_sending_done == False:
        try:
            pkts = sniff(filter="arp and (ether src not %s and ether src not %s)" % (router_pkt[1][ARP].hwsrc, ether_frame.src), count=1, timeout=8)
            active_users[pkts[0][ARP].hwsrc] = pkts[0][ARP].psrc
            if users_ip_adresses.count(pkts[0][ARP].psrc) < 1:
                users_ip_adresses.append(pkts[0][ARP].psrc)
            if len(active_users) == number_of_users:
                break
        except:
            continue
    add_active_users_to_database(active_users, number_of_users)

def send_packets(ip_adresses_list, is_dup_true, number_of_users=None):

    global is_sending_done
    global active_users
    global conn
    global cur
    global users_ip_adresses
    is_sending_done = False
    if is_dup_true:
        for ip in ip_adresses_list:
            sendp(Ether()/ARP(pdst=ip), verbose=False)
            if len(active_users) == number_of_users:
                break
        is_sending_done = True
    else:
        print "[+] Finding active users process have started. Please wait..."
        is_quit = False
        for ip in ip_adresses_list:
            ans, unans = srp(Ether()/ARP(pdst=ip), verbose=False, retry=2, timeout=0.3)
            for send, rcv in ans:
                active_users[rcv.hwsrc] = rcv.psrc
                if users_ip_adresses.count(rcv.psrc) < 1:
                    users_ip_adresses.append(rcv.psrc)
                if len(active_users) == number_of_users:
                    is_quit = True
                    break
            if is_quit:
                is_sending_done = True
                break
        add_active_users_to_database(active_users, number_of_users)
def path_to_google():
    print "[+] Finding path to google process have started."
    private_ip_list = ["192.168.", "10.", "172.", "127."]
    insert_data = """INSERT INTO path_to_google(ip_adress, is_private_ip, geo_location) VALUES(%s, %s, %s)"""
    cur.execute("""DELETE FROM path_to_google""")
    conn.commit()
    for i in range(1,15):
        ans, unans = sr(IP(dst="8.8.8.8", ttl=i)/ICMP(), verbose=False, retry=3, timeout=0.5)
        for send, rcv in ans:
            if rcv[ICMP].type == 11 and (private_ip_list[0] in rcv[IP].src or private_ip_list[1] in rcv[IP].src or private_ip_list[2] in rcv[IP].src or private_ip_list[3] in rcv[IP].src):  
                cur.execute(insert_data, (rcv[IP].src, "True", "NA" ))
                conn.commit()
            elif rcv[ICMP].type == 11:
                if geolite2.lookup(rcv[IP].src) is not None:
                    match = geolite2.lookup(rcv[IP].src)
                    cur.execute(insert_data, (rcv[IP].src, "False", match.timezone))
                    conn.commit()
                else:
                    cur.execute(insert_data, (rcv[IP].src, "False", "NA" ))
                    conn.commit()
            else:
                if geolite2.lookup(rcv[IP].src) is not None:
                    match = geolite2.lookup(rcv[IP].src)
                    cur.execute(insert_data, (rcv[IP].src, "False", match.timezone))
                    conn.commit()
                    return None
                else:
                    cur.execute(insert_data, (rcv[IP].src, "False", "NA" ))
                    conn.commit()
                    return None
def distinguish_windows_machines():
    global users_ip_adresses
    count = 0
    used_ip =[]
    print "[+] Distinguishing Windows machines process have started..."
    insert_data = """INSERT INTO windows_users(ip_adress, mac_adress) VALUES(%s, %s)"""
    cur.execute("""DELETE FROM windows_users""")
    conn.commit()
    while True:
        if len(users_ip_adresses) > count:
            active_users_temp = active_users
            ip = users_ip_adresses[count]
            ans, unans = sr(IP(dst=ip)/ICMP(), verbose=False, retry=2, timeout=0.8)
            count = count + 1
            for send, rcv in ans:
                if rcv.ttl > 64 and rcv.ttl <= 128:
                    for key, value in active_users_temp.iteritems():
                        if active_users_temp[key] == ip:
                            cur.execute(insert_data, (ip, key))
                            conn.commit()
        else:
            continue
def signal_handler(signal, frame):
    global process_collect
    if is_sending_done == False:
        add_active_users_to_database(active_users)
    process_collect.terminate()
    write_report()
    print "[-] Exit"
    sys.exit(0)
def write_report():
    print "[+] Report is preparing..."
    cur.execute("""SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'""")
    table_names = cur.fetchall()
    if os.path.exists(r"./report.txt"):
        os.remove(r"./report.txt")
    report_file = open(r"./report.txt", "w", 0)
    report_file.write("\t\t\t\t FULL REPORT \n\n")
    for i in table_names:
        cur.execute("""SELECT * FROM {0}""".format(i[0]))
        table_datas = cur.fetchall()
        cur.execute("""SELECT column_name FROM information_schema.columns WHERE table_name='{0}'""".format(i[0])) 
        table_columns = cur.fetchall()
        table_columns = [i[0] for i in table_columns]
        report_file.write(tabulate(table_datas, table_columns) + "\n\n")
    report_file.close()

if __name__ == '__main__':
    ip_adress = raw_input("[*] Please give local ip adress: ")
    subnet_mask = raw_input("[*] Please give your subnet in CIDR format(24,16,8,23...etc): ")
    is_dup_true = raw_input("[*] Is there any problem that might effect arp scan in your local network like (DUP)[y/yes/ok/Y] (default=No): ")
    ip_adresses_list = [] #Local network all possible IPs
    arguments = sys.argv
    number_of_users = None
    try:
        if arguments[1] == '-c' or arguments[1] == '-C':
            number_of_users = int(arguments[2])
    except:
        print "[+] Program usage --> sudo python localscan.py -c <number_of_users>"
        sys.exit(1)
    connect()
    
    process_collect = multiprocessing.Process(target=collect_broadcast_data, args=[])
    process_collect.start()
    
    if not os.path.exists(r"./Datas"):
        os.mkdir("Datas")
    for ip in IPNetwork(ip_adress + "/" + subnet_mask).iter_hosts():
        ip_adresses_list.append(str(ip))
   
    if is_dup_true in ["y", "Y", "Yes", "yes", "ok", "Ok", "YES"]:
        is_dup_true = True
    else:
        is_dup_true = False

    if is_dup_true:
        thread1 = threading.Thread(target=send_packets, args=[ip_adresses_list, is_dup_true, number_of_users])
        thread2 = threading.Thread(target=sniff_packets, args=[ip_adresses_list[0], number_of_users])
        thread3 = threading.Thread(target=distinguish_windows_machines, args=[])

        thread1.daemon = True
        thread2.daemon = True
        thread3.daemon = True

        thread1.start()
        thread2.start()
        thread3.start()
        
    else:
        thread1 = threading.Thread(target=send_packets, args=[ip_adresses_list, is_dup_true, number_of_users])
        thread3 = threading.Thread(target=distinguish_windows_machines, args=[])
        thread1.daemon = True
        thread3.daemon = True

        thread1.start()
        thread3.start()

    path_to_google()

    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()
    while True:
        time.sleep(100)
