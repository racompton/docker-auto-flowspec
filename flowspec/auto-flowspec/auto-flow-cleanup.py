#!/usr/bin/env python2
# Initial: 09/08/17  Updated: 10/05/17
# commit version 2.23
# All rights reserved - Charter Communications
from socket import socket, AF_INET, SOCK_DGRAM
import errno
import sys
import os
import time
from time import gmtime, strftime, sleep
import logging
from datetime import date, timedelta, datetime
import mysql.connector


def query_db():
    '''
    Query database - get pair & check if exceeds x hrs
    If else to call another function
    '''
    flowspecdb_cnx = mysql.connector.connect(user='flowspecuser',
                                             password='FLOWSPEC_USER_PASS',
                                             host='127.0.0.1',
                                             database='flowspecdb')
    flowspecdb_cursor = flowspecdb_cnx.cursor()
    status = "active"
    try:  # add select of IP Address
        entry_count = flowspecdb_cursor.execute(
            "SELECT dst_ip, time_start FROM rules WHERE state='%s'" % (status))
        entries = flowspecdb_cursor.fetchall()
    except mysql.connector.IntegrityError:
        return 0
    if len(entries) > 0:  # Edit after modifying selection
        print("Entry count greater than 0.")
        for row in entries:
            dst_ip = row[0]
            time_last_seen = row[1]
            time_format = '%Y-%m-%d %H:%M:%S'
            print(str(time_last_seen))
            print(str(datetime.utcnow()))
            #time_last_convert = datetime.datetime.strptime(time_last_seen, time_format)
            if datetime.utcnow() - time_last_seen > timedelta(hours=MAX_RULE_AGE):
                # if 2 == 2:
                print "withdraw, update to inactive"
                check = withdraw(dst_ip)
		timestamp = strftime("%Y-%m-%d %H:%M:%S", gmtime())
                if check:
                    status_down = "inactive"
                    try:
                        flowspecdb_cursor.execute ("""
                           UPDATE rules
                           SET state=%s, time_stop=%s
                           WHERE dst_ip=%s AND state=%s
                        """, (status_down, timestamp,  dst_ip,  status))
                        flowspecdb_cnx.commit()
                    except mysql.connector.IntegrityError:
                        return 0
            else:
                continue


def withdraw(dest):
    """
    This function defines all the FlowSpec rules to be withdrawn via the iBGP Update.
    ////***update*** Add port-range feature similar to announce() - ADDED in TBowlby's code.

    Args:
        dest (str): IP Address of the Victim host.

    Calls:
        send_curl(messages): Calls a function to execute curl API commands to be sent to the Flask Server.

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
        'withdraw flow route { match { destination %s/32; source-port =17 =19 =69 =111 =137 =138 =161 =162 =389 =520 =1434 =1701 =5353 =11211; protocol udp; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; source-port =53; destination-port =4444; protocol udp; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; protocol udp; fragment is-fragment; } then { discard; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; protocol tcp; tcp-flags [ syn ]; } then { rate-limit SYN_RATE_LIMIT; community [ COMMUNITY ]; } }' % dest,
        'sleep',
        'withdraw flow route { match { destination %s/32; } then { rate-limit MAX_SPEED; community [ COMMUNITY ]; } }' % dest,
    ]
    send_curl(messages)
    return 1


def send_curl(update=[]):
    """
    This function sends curl API commands to the Flask Server to either announce or withdraw a series of routes.

    Args:
        update (list): Series of announce/withdraw commands.

    Calls:
        withdraw(dst_ip): Calls a function to start the process of withdrawing FlowSpec routes from the Virtual
        Route Reflector.

    Note:
        Update the IP Address and Port number if the Flask Server is running on a different socket.

    Raises:
        silent error: If the Flask Server is not running the curl commands will be ignored and no exabgp process
        will be initiated.

    """
    for message in update:
        if message == "sleep":
            time.sleep(0.05)
        else:
            os.system(
                "curl --form \"command=%s\" http://localhost:5000/" % message)

while True:
    # Run the database query to find stale Flowspec rules and then call ExaBGP to remove them 
    bool = query_db()
    # Sleep for one hour and then do the query function
    time.sleep(3600)