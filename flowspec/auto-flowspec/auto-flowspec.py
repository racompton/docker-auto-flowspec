#!/usr/bin/env python2
# Initial: 09/08/17  Updated: 10/05/17
# commit version 2.23
# All rights reserved - Charter Communications
"""
This program is an Auto FlowSpec route generator for DDoS Mitigation. It listens for syslog messages from Arbor. DDoS
attacks alerts are received via the syslog. It will announce FlowSpec routes when a DDoS attack starts and will withdraw
routes when the corresponding DDoS attack stops. To update routes, it sends the route messages via requests to a Flask
Server running in the background. The Flask Server will simply send the message to the Standard Out. The ExaBGP function
runs in the background too which will read the Standard Out messages and send a iBGP Route Update to the Virtual Route
Reflector.

"""

from socket import socket, AF_INET, SOCK_DGRAM
import errno
import sys
import os
import time
from time import gmtime, strftime, sleep
import logging
from datetime import date, timedelta, datetime
import mysql.connector
import requests
#-------------------------------------------------------------------------


def update(**kwargs):
    """
    -*-*- Adding timestamp
    This function inserts in an existing MySQL database, a new set of Alert ID, Message Text, Destination IP and 
    State as obtained from the syslog message from Arbor. Then it calls the announce() function.

    Args:
        **kwargs (dict): Key-value pair of syslog parameters.

    Calls:
        announce(dst_ip): Calls a function to start the process of announcing FlowSpec routes to the Virtual
        Route Reflector.

    Raises:
        OperationalError: If it is unable to connect to the mysql database.

    """
    global log_file
    flowspecdb_cnx = mysql.connector.connect(user='flowspecuser',
                                             password='FLOWSPEC_USER_PASS',
                                             host='127.0.0.1',
                                             database='flowspecdb')
    flowspecdb_cursor = flowspecdb_cnx.cursor()
    try:
        addrule = ("INSERT INTO rules"
                   "(alert_id, message, dst_ip, state, time_start)"
                   "VALUES (%s, %s, %s, %s, %s)")
        alert_id = kwargs['alert_id']
        message = kwargs['message']
        dst_ip = kwargs['dst_ip']
        state = kwargs['state']
        time_start = kwargs['time_start']
        flowspecdb_cursor.execute(
            addrule, (alert_id, message, dst_ip, state, time_start))
        flowspecdb_cnx.commit()
    except mysql.connector.IntegrityError:
        return
    print "Announcing FlowSpec routes..."
    with open(log_file, "a") as myfile:
        myfile.write("\nAnnouncing FlowSpec routes...\n\n\n")
        myfile.close
    announce(dst_ip)

def remove(input_alert_id):
    """
    This function retrieves the Victim IP from an existing MySQL database, which matches the Alert ID. Extracted (and
    non-malicious) IP will be used to call the withdraw function. It will also delete the entry from the MySQL
    database.
    ***update*** Add filter to handle 'no Alert ID matching the VictimIP'.

    Args:
        input_alert_id (str): Alert ID of the syslog message.

    Calls:
        withdraw(dst_ip): Calls a function to start the process of withdrawing FlowSpec routes from the Virtual
        Route Reflector.

    Raises:
        OperationalError: If it is unable to connect to the MySQL database.
        silent - error: If it is not able to find the matching Victim IP then it not withdraw the FlowSpec routes.
    """
    global log_file
    input_alert_id = int(input_alert_id)
    flowspecdb_cnx = mysql.connector.connect(user='flowspecuser',
                                             password='FLOWSPEC_USER_PASS',
                                             host='127.0.0.1',
                                             database='flowspecdb')
    flowspecdb_cursor = flowspecdb_cnx.cursor()
    queryrule = ("SELECT alert_id, state, dst_ip FROM rules "
                 "WHERE alert_id=%s and state=%s")
    known_state = unicode('active')
    flowspecdb_cursor.execute(queryrule, (input_alert_id, known_state))
    for alert_id, state, dst_ip in flowspecdb_cursor:
        if (alert_id == input_alert_id) and (state == known_state):
            print "Victim IP matching the Alert ID found in our records"
            print "Withdrawing FlowSpec routes..."
            with open(log_file, "a") as myfile:
                myfile.write(
                    "\nVictim IP matching the Alert ID found in our records\n")
                myfile.write("\nWithdrawing FlowSpec routes...\n\n\n")
                myfile.close
            result = withdraw(dst_ip)
            if result == 'route_withdrawn':
                state = 'inactive'
                timestamp = strftime("%Y-%m-%d %H:%M:%S", gmtime())
                flowspecdb_cursor.execute("""
                                    UPDATE rules
                                    SET state=%s, time_stop=%s
                                    WHERE alert_id=%s AND dst_ip=%s AND state=%s
                                """, (state, timestamp, input_alert_id, dst_ip, known_state))
                flowspecdb_cnx.commit()

def announce(dest):
    """
    This function defines all the FlowSpec rules to be announced via the iBGP Update.

    Args:
        dest (str): IP Address of the Victim host.

    Calls:
        send_requests(messages): Calls a function to execute requests API commands to be sent to the Flask Server.

    """
    messages = [
# Rate limit DNS amplification traffic
        'announce flow route { match { destination %s/32; source-port =53; protocol udp; } then { rate-limit DNS_RATE_LIMIT; community [ COMMUNITY ]; } }' % dest,
        'sleep',
# Block all NTP Monlist traffic
        'announce flow route { match { destination %s/32; source-port =123; protocol udp; packet-length =468; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
# Rate limit ICMP traffic
        'announce flow route { match { destination %s/32; protocol icmp; } then { rate-limit ICMP_RATE_LIMIT; community [ COMMUNITY ]; } }' % dest,
        'sleep',
# Block UDP QOTD (17), Chargen (19), TFTP (69), RPC (111), NetBIOS (137/138), SNMP (161/162), LDAP (389), RIP (520), MSSQL (1434), L2TP (1701), SSDP (1900), mDNS (5353), and Memecache (11211) amplificaton traffic
        'announce flow route { match { destination %s/32; source-port =17 =19 =69 =111 =137 =138 =161 =162 =389 =520 =1434 =1701 =5353 =11211; protocol udp; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
# Block all DNS traffic with a destination port of 4444 (commonly used in DNS amplification attacks)
        'announce flow route { match { destination %s/32; source-port =53; destination-port =4444; protocol udp; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
# Block all UDP fragments
        'announce flow route { match { destination %s/32; protocol udp; fragment is-fragment; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
# Rate limit inbound SYN traffic
        'announce flow route { match { destination %s/32; protocol tcp; tcp-flags [ syn ]; } then { rate-limit SYN_RATE_LIMIT; community [ COMMUNITY ]; } }' % dest,
        'sleep',
# Rate limit all other traffic in case the attack is using a random port
        'announce flow route { match { destination %s/32; } then { rate-limit 12500000; community [ COMMUNITY ]; } }' % dest,
    ]
    send_requests(messages)


def withdraw(dest):
    """
    This function defines all the FlowSpec rules to be withdrawn via the iBGP Update.
    ////***update*** Add port-range feature similar to announce() - ADDED in TBowlby's code.

    Args:
        dest (str): IP Address of the Victim host.

    Calls:
        send_requests(messages): Calls a function to execute requests API commands to be sent to the Flask Server.

    Returns:
        Returns the string 'route_withdrawn' to confirm the withdrawal of routes so the entry can be deleted
        from the MySQL database.

    """
    messages = [
        'withdraw flow route { match { destination %s/32; source-port =53; protocol udp; } then { rate-limit DNS_RATE_LIMIT; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; source-port =123; protocol udp; packet-length =468; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; protocol icmp; } then { rate-limit ICMP_RATE_LIMIT; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; source-port =17 =19 =69 =111 =137 =138 =161 =162 =389 =520 =1434 =1701 =1900 =5353 =11211; protocol udp; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; source-port =53; destination-port =4444; protocol udp; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; protocol udp; fragment is-fragment; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; protocol tcp; tcp-flags [ syn ]; } then { rate-limit SYN_RATE_LIMIT; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; } then { rate-limit MAX_SPEED; community [ COMMUNITY ]; } }' % dest,
    ]
    send_requests(messages)
    return 'route_withdrawn'


def send_requests(update=[]):
    """
    This function sends requests API commands to the Flask Server to either announce or withdraw a series of routes.

    Args:
        update (list): Series of announce/withdraw commands.

    Calls:
        withdraw(dst_ip): Calls a function to start the process of withdrawing FlowSpec routes from the Virtual
        Route Reflector.

    Note:
        Update the IP Address and Port number if the Flask Server is running on a different socket.

    Raises:
        silent error: If the Flask Server is not running the requests commands will be ignored and no exabgp process
        will be initiated.

    """
    for message in update:
        if message == "sleep":
            time.sleep(0.05)
        else:
	    payload = {}
	    payload['command'] = message
	    flowspec_update = requests.post("http://localhost:5000/", data=payload)
	    print(flowspec_update.text)

app_time = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
os.system('clear')  # clear the screen
# string indicating start of DDoS attack in syslog
varlocal_syslog_trigger_on = "DDOS_START_MESSAGE"
# string indicating Residential Customers Managed Object is under attack - can be modified via Arbor
varlocal_syslog_trigger_on_2 = "DDOS_CUTSOMER_MATCH"
# string indicating DDoS attack has stopped
varlocal_syslog_trigger_on_3 = "DDOS_STOP_MESSAGE"
local_ip = '0.0.0.0'
syslog_port = 514  # listen on port
log_file = "/var/log/auto-flowspec/auto-flowspec.log"
varlocal_log_to_file = True  # to log in file or not
alert_ip = {'alertID': 'Victim IP'}  # mapping alertId to VictimIP
false_ip = "0.0.0.0"
buf = 1500
addr = (local_ip, syslog_port)
UDPSock = socket(AF_INET, SOCK_DGRAM)  # Create socket and bind to address
UDPSock.bind(addr)
header = "\n\n------------------ Charter Communications: Auto FlowSpec - DDoS Mitigator READY! (" + app_time + ") Listening on UDP " + str(
    syslog_port) + "  ------------------\n\n"
print header
if varlocal_log_to_file == True:
    with open(log_file, "a") as myfile:
        myfile.write(header)
        myfile.close
#--------------------- Receive messages ----------------------------------
while True:
    """
    Listen for syslog messages. Parse the message contents to decide whether to announce/withdraw routes or do
    nothing and to find Alert ID & Victim IP. Also log the messages.

    """
    data, addr = UDPSock.recvfrom(buf)
    if not data:
        print("Client has exited!")
        if varlocal_log_to_file == True:
            with open(log_file, "a") as myfile:
                myfile.write("\nClient has exited!\n")
                myfile.close
        break
    else:
        data_str = data.decode('utf8')
        print "Received message: ", data_str
        if data_str.find("DDOS_HIGH_IMPORTANCE") == -1:
            print "Importance is NOT high. System will not proceed to do auto mitigation"
            with open(log_file, "a") as myfile:
                myfile.write(data_str)
                myfile.write("\nImportance is NOT high\n")
                myfile.close
            continue
        if data_str.find(varlocal_syslog_trigger_on_3) != -1:
            '''
            If its a 'Stop' message then withdraw FlowSpec routes after
            finding Victim IP corresponding to the AlertID.
            '''
            print "Stop statement found"
            with open(log_file, "a") as myfile:
                myfile.write(data_str)
                myfile.write("\nIdentified as stop statement\n")
                myfile.close
            alert_id = ''
            alert_id_pos = data_str.index("alert #")
            real_pos = int(alert_id_pos + 7)
            alert_id_len_pos = data_str.index(", start")
            alert_id = data_str[real_pos:alert_id_len_pos]
            '''
            max length 10 chars - preventing BufferOverflow
            '''
            alert_id = alert_id[:10]
            remove(alert_id)
        elif data_str.find(varlocal_syslog_trigger_on) == -1 or data_str.find(varlocal_syslog_trigger_on_2) == -1:
            print "Not a valid DDoS start message"
            with open(log_file, "a") as myfile:
                myfile.write(data_str)
                myfile.write("\nNot a valid DDoS start message\n")
                myfile.close
        else:
            '''
            If its a 'Start' message then announce FlowSpec routes for the
            specific Victim IP.
            '''
            header = "\nValid START syslog msg [\n" + data_str + "\n]"
            print header
            if varlocal_log_to_file == True:
                with open(log_file, "a") as myfile:
                    myfile.write(data_str)
                    myfile.write("\nIdentified as START message\n")
                    myfile.close
            alert_id = ''
            victim_ip = ''
            alert_id_pos = data_str.index("alert #")
            real_pos = int(alert_id_pos + 7)
            alert_id_len_pos = data_str.index(", start")
            alert_id = data_str[real_pos:alert_id_len_pos]
            '''
            max length 10 chars - preventing BufferOverflow
            '''
            alert_id = alert_id[:10]
            print "AlertID is: ", alert_id
            victim_ip_pos = data_str.index("host")
            real_pos_ip = int(victim_ip_pos + 5)
            victim_ip_len_pos = data_str.index(", signatures")
            victim_ip = data_str[real_pos_ip:victim_ip_len_pos]
            '''
            max length 15 chars - preventing BufferOverflow
            '''
            victim_ip = victim_ip[:15]
            print "VictimIP is: ", victim_ip
            alert_ip[str(alert_id)] = str(victim_ip)
            print alert_ip
            if victim_ip == false_ip:
                print "ERROR: Malicious syslog message. VictimIP sent as 0.0.0.0 Investigate!"
                with open(log_file, "a") as myfile:
                    myfile.write(
                        "\nERROR: Malicious syslog message. VictimIP sent as 0.0.0.0 Investigate!\n")
                    myfile.close
                    continue
            timestamp = strftime("%Y-%m-%d %H:%M:%S", gmtime())
            syslog_message = {'alert_id': alert_id, 'message':
                              'start', 'dst_ip': victim_ip, 'state': 'active', 'time_start': timestamp}
            with open(log_file, "a") as myfile:
                myfile.write("\nAlert ID: " + alert_id + "Victim IP: " + victim_ip + "\n")
                myfile.close
            update(**syslog_message)

UDPSock.close()
