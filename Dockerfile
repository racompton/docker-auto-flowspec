# Dockerfile for setting up auto-flowspec contoller
#
# To install docker run: 
# sudo apt-get install -y docker.io
#
# To make the docker daemon start at boot:
# sudo systemctl enable docker
#
# To build the container run: 
# sudo docker build -t auto-flowspec .
#
# Create a shared directory called /var/log/auto-flowspec with the command:
# sudo mkdir /var/log/auto-flowspec
#
# To start the container run:
# sudo docker run --name auto-flowspec -v /var/log/auto-flowspec:/var/log/auto-flowspec -d --restart unless-stopped -p 179:179 -p 514:514/udp -p 9001:9001  --network host auto-flowspec


FROM ubuntu:16.04

#Created by Rich Compton rich.compton@charter.com 1-24-18

#Set this if the Docker container is behind a proxy:
#ENV http_proxy http://<PROXY IP>:80
#ENV https_proxy http://<PROXY IP>:80
#ENV no_proxy=localhost,172.16.0.0/12,127.0.0.0/8,127.0.1.1,127.0.1.1*,local.home
#ENV NO_PROXY=localhost,172.16.0.0/12,127.0.0.0/8,127.0.1.1,127.0.1.1*,local.home

# Upgrade the OS
RUN apt-get update && apt-get upgrade -y

# Define mysql root password
ENV MYSQL_ROOT_PASS=mysqlrootpassword

# Set the mysql root password
RUN echo "mysql-server mysql-server/root_password password $MYSQL_ROOT_PASS" | debconf-set-selections
RUN echo "mysql-server mysql-server/root_password_again password $MYSQL_ROOT_PASS" | debconf-set-selections


# Install necessary packages
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y python-setuptools python-flask curl wget python-requests git supervisor mysql-server python-minimal python-mysql.connector vim lsof unzip

# Configure all the environment variables below before building the container:

# Define the user for the Supervisor web interface
ENV SUPERVISOR_USER=admin

# Define the pass for the Supervisor web interface
ENV SUPERVISOR_PASS=supervisorpassword

# Define the password for the flowspecuser
ENV FLOWSPEC_USER_PASS=flowspecpassword

# Define the Exabgp Neighbor #1 IP
ENV NEIGHBOR1_IP=96.34.194.100

# Define the Exabgp Neighbor #1 description (no spaces)
ENV NEIGHBOR1_DESC=flowspec-rtr01

# Define the MD5 password for Neighbor 1
ENV NEIGHBOR1_MD5=md5password

# Define the Exabgp Neighbor 1 Peer ASN
ENV PEER1_AS=65206

# Define the Exabgp Neighbor #2 IP
ENV NEIGHBOR2_IP=192.0.2.2

# Define the Exabgp Neighbor #2 description (no spaces)
ENV NEIGHBOR2_DESC=flowspec-rtr02

# Define the MD5 password for Neighbor 2
ENV NEIGHBOR2_MD5=md5password

# Define the Exabgp Neighbor 1 Peer ASN
ENV PEER2_AS=65000

# Definie the Exabgp Router ID (normally the IPv4 IP of the host OS)
ENV ROUTER_ID=172.18.11.219

# Define the Exabgp Local Address (Normally the same IP as the ROUTER_ID, the IPv4 IP of the host OS)
ENV LOCAL_ADDRESS=172.18.11.219

# Define the Exabgp Local ASN
ENV LOCAL_AS=65206

# Define the BGP Community to tag Flowspec routes with
ENV COMMUNITY=64777:00020

# Define the DNS rate limit speed in Bytes for inbound traffic with UDP source port 53
ENV DNS_RATE_LIMIT=3750

# Define the ICMP rate limit speed in Bytes for inbound traffic with IP Proto 1
ENV ICMP_RATE_LIMIT=3750

# Define the SYN rate limit speed in Bytes for inbound traffic with the SYN flag sent
ENV SYN_RATE_LIMIT=3750

# Define the maximum speed in Bytes for all othe traffic to the victim
ENV MAX_SPEED=12500000

# Define the maximum time in hours for Flowspec rules to remain active.  After this time, the rules will be removed even if no syslog message has been received stating that the attack has finished.
ENV MAX_RULE_AGE=6 

# Define the syslog string to look for to identify a DDoS start message 
ENV DDOS_START_MESSAGE="start"

# Define the syslog string to look for to identify the Managed Objects that you want to mitigate with Flowspec rules
ENV DDOS_CUTSOMER_MATCH="Residential"

# Define the syslog string to look for to identify a DDoS stop message 
ENV DDOS_STOP_MESSAGE=" is now done,"

# Define the syslog string to look for to identify a high level alert
ENV DDOS_HIGH_IMPORTANCE="importance 2"

# That's it.  No more changes are necessary after this point.

# Change the working directory
WORKDIR /opt/

# Make a directory called opt/auto-flowspec/
RUN mkdir /opt/auto-flowspec/

# Copy over the contents of the auto-flowspec directory over
COPY flowspec/auto-flowspec/* /opt/auto-flowspec/

# Copy the stable version of ExaBGP (3.4) over 
#COPY 3.4.zip /tmp/
#WORKDIR /tmp/
#RUN unzip 3.4.zip
#RUN mv /tmp/exabgp-3.4/ /opt/exabgp/

# Get ExaBGP 3.4 code from GitHub 
WORKDIR /tmp/
RUN wget https://github.com/Exa-Networks/exabgp/archive/3.4.zip
RUN unzip 3.4.zip
RUN mv /tmp/exabgp-3.4/ /opt/exabgp/


# Make an auto-flowspec log directory to stick all the logs in.  This diretory will be mounted on the host OS.
RUN mkdir /var/log/auto-flowspec/

# Set up supervisord to have a web page for viewing the status
COPY flowspec/supervisord.conf  /etc/supervisor/supervisord.conf

# Define the supervisord username
RUN sed -i -e "s/SUPERVISOR_USER/$SUPERVISOR_USER/g" /etc/supervisor/supervisord.conf

# Create the SHA1 password for supervisord and replace the default one
RUN HASH_PASS=`python -c "import hashlib; m = hashlib.sha1(); m.update('$SUPERVISOR_PASS'); print m.hexdigest()"` && sed -i -e "s/HASH_PASS/$HASH_PASS/g" /etc/supervisor/supervisord.conf  

# Set up supervisord to run Auto-Flowspec Python Script
COPY flowspec/auto-flowspec-supervisor.conf /etc/supervisor/conf.d/auto-flowspec-supervisor.conf

# Set up supervisord to run Auto-Cleanup Shell Script (runs and then sleeps one hour and then runs again)
COPY flowspec/auto-cleanup-supervisor.conf /etc/supervisor/conf.d/auto-cleanup-supervisor.conf

# Set up supervisord to run ExaBGP
COPY flowspec/exabgp-supervisor.conf /etc/supervisor/conf.d/exabgp-supervisor.conf

# Set up supervisord to run MySQL
COPY flowspec/mysql-supervisor.conf /etc/supervisor/conf.d/mysql-supervisor.conf

## Create ExaBGP config file
COPY flowspec/exabgp.conf /opt/exabgp/etc/exabgp/exabgp.conf

# Create the exabgp.env file
COPY flowspec/exabgp.env /opt/exabgp/etc/exabgp/exabgp.env

# Modify auto-flowspec.py file and replace password with specified password
RUN   sed -i -e "s/FLOWSPEC_USER_PASS/$FLOWSPEC_USER_PASS/g" /opt/auto-flowspec/auto-flowspec.py

# Modify auto-flow-cleanup.py file and replace password with specified password
RUN   sed -i -e "s/FLOWSPEC_USER_PASS/$FLOWSPEC_USER_PASS/g" /opt/auto-flowspec/auto-flow-cleanup.py


# Modify exabgp.conf file and replace values with specified values
RUN   sed -i -e "s/NEIGHBOR1_IP/$NEIGHBOR1_IP/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/NEIGHBOR1_DESC/$NEIGHBOR1_DESC/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/PEER1_AS/$PEER1_AS/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/NEIGHBOR1_MD5/$NEIGHBOR1_MD5/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/NEIGHBOR2_IP/$NEIGHBOR2_IP/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/NEIGHBOR2_DESC/$NEIGHBOR2_DESC/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/NEIGHBOR2_MD5/$NEIGHBOR2_MD5/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/PEER2_AS/$PEER2_AS/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/ROUTER_ID/$ROUTER_ID/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/LOCAL_AS/$LOCAL_AS/g" /opt/exabgp/etc/exabgp/exabgp.conf
RUN   sed -i -e "s/LOCAL_ADDRESS/$LOCAL_ADDRESS/g" /opt/exabgp/etc/exabgp/exabgp.conf

# Modify the auto-flowspec.py and auto-flow-cleanup.py files to define the COMMUNITY that the Flowspec rules will be tagged with
RUN   sed -i -e "s/DNS_RATE_LIMIT/$DNS_RATE_LIMIT/g" /opt/auto-flowspec/auto-flowspec.py
RUN   sed -i -e "s/DNS_RATE_LIMIT/$DNS_RATE_LIMIT/g" /opt/auto-flowspec/auto-flow-cleanup.py
RUN   sed -i -e "s/ICMP_RATE_LIMIT/$ICMP_RATE_LIMIT/g" /opt/auto-flowspec/auto-flowspec.py
RUN   sed -i -e "s/ICMP_RATE_LIMIT/$ICMP_RATE_LIMIT/g" /opt/auto-flowspec/auto-flow-cleanup.py
RUN   sed -i -e "s/SYN_RATE_LIMIT/$SYN_RATE_LIMIT/g" /opt/auto-flowspec/auto-flowspec.py
RUN   sed -i -e "s/SYN_RATE_LIMIT/$SYN_RATE_LIMIT/g" /opt/auto-flowspec/auto-flow-cleanup.py
RUN   sed -i -e "s/MAX_SPEED/$MAX_SPEED/g" /opt/auto-flowspec/auto-flowspec.py
RUN   sed -i -e "s/MAX_SPEED/$MAX_SPEED/g" /opt/auto-flowspec/auto-flow-cleanup.py

# Modify the auto-flowspec.py and auto-flow-cleanup.py files to define the rate limit speeds
RUN   sed -i -e "s/COMMUNITY/$COMMUNITY/g" /opt/auto-flowspec/auto-flowspec.py
RUN   sed -i -e "s/COMMUNITY/$COMMUNITY/g" /opt/auto-flowspec/auto-flow-cleanup.py

# Modify the auto-flow-cleanup.py file to specify the maximum age that flowspec rules can have
RUN   sed -i -e "s/MAX_RULE_AGE/$MAX_RULE_AGE/g" /opt/auto-flowspec/auto-flow-cleanup.py

# Modify the auto-flowspec.py scipt to define the string matches for starting/stopping a high level attack with the specified Managed Object name
RUN   sed -i -e "s/DDOS_START_MESSAGE/$DDOS_START_MESSAGE/g" /opt/auto-flowspec/auto-flowspec.py
RUN   sed -i -e "s/DDOS_CUTSOMER_MATCH/$DDOS_CUTSOMER_MATCH/g" /opt/auto-flowspec/auto-flowspec.py
RUN   sed -i -e "s/DDOS_STOP_MESSAGE/$DDOS_STOP_MESSAGE/g" /opt/auto-flowspec/auto-flowspec.py
RUN   sed -i -e "s/DDOS_HIGH_IMPORTANCE/$DDOS_HIGH_IMPORTANCE/g" /opt/auto-flowspec/auto-flowspec.py

# Create the Flask API for ExaBGP and make it executable
COPY flowspec/exabgp-app.py /opt/exabgp/run/
RUN chmod 755 /opt/exabgp/run/exabgp-app.py


# Modify the flowspec user password for access to the flowspecdb in MySQL 
RUN   sed -i -e "s/FLOWSPEC_USER_PASS/$FLOWSPEC_USER_PASS/g" /opt/auto-flowspec/flowspecdb-schema.sql

# Create a directory for mysqld to put it's PID and then make the mysql user the owner of the directory so that user can write to the directory
RUN mkdir /var/run/mysqld
RUN chown mysql /var/run/mysqld

# Start up the mysql database so we can create the database
# This is all one line because mysql will stop if it's on seperate lines
# sleep 5 give the mysql daemon a few seconds to start up before we create the database and create the tables
RUN /bin/bash -c "/usr/bin/mysqld_safe &" && \
sleep 5 && \
mysql -u root -p$MYSQL_ROOT_PASS  -e "CREATE DATABASE flowspecdb" && \
mysql -u root -p$MYSQL_ROOT_PASS flowspecdb < /opt/auto-flowspec/flowspecdb-schema.sql

# Copy over the run-mysql.sh script which will start mysql and create the flowspecdb if it doesn't exist yet
#COPY flowspec/run-mysql.sh /opt/auto-flowspec/
# Make the script executable
#RUN chmod 755 /opt/auto-flowspec/run-mysql.sh 

# Expose BGP port for ExaBGP
EXPOSE 179
# Expose Syslog Port for collecting Syslog messages from ArborSP
EXPOSE 514/udp
# Expose Supervisord HTTP Server port
EXPOSE 9001

# Run the supervisord daemon which will start mysql, auto-flowspec, and auto-clean-up.py 
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]


