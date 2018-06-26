# Auto-Flowspec Docker Container

> https://chalk.charter.com/x/GIhlDQ 

## Description
This is a self-contained flowspec controller in a container.  The auto-flowspec.py script will listen for syslog messages from an Arbor SP PI device.  If the syslog message contains "Residential" and "importance 2" (high level alert) and doesn't contain "is now done" (attack is over) then a API call will be made with Flowspec rules to a flask server which controls ExaBGP.  ExaBGP will then send the rules to one or two route reflectors.  The alert details are also written to a MySQL database.
Once a syslog message saying that the attack "is now done", another API call is made to ExaBGP to remove the rules.  There is also a clean-up script that will remove any rules that have not been withdrawn after a specified amount of time.

## Installation
1. Clone the git repository:
`git clone ssh://git@apollo00.charterlab.com:222/security/docker-auto-flowspec.git`
2. Install docker with the command:
`sudo apt-get install -y docker.io`
3. Create the docker network with the command:
` sudo docker network create --subnet 192.168.0.0/24 auto-flowspec-net`
4. Edit the Dockerfile to populate the relevant environment variables then build the container with the command: 
`sudo docker build sudo docker --no-cache -t auto-flowspec .`
5. Then run the container with the command: 
`sudo docker run --name auto-flowspec -v /var/log/auto-flowspec:/var/log/auto-flowspec -d --restart unless-stopped -p 179:179 -p 514:514/udp -p 9001:9001 --net auto-flowspec-net --ip 192.168.0.2 auto-flowspec`

## Development setup

https://chalk.charter.com/x/GIhlDQ

##Logroate
The log rotate config files need to be copied over to  /etc/logrotate.d/exabgp-logrotate and /etc/logrotate.d/auto-flowspec-logrotate

## Setting up Splunk Forwarding
1. Download the latest splunk forwarder .deb or .rpm package
2. Install the splunk forwarder
  `sudo dpkg -i splunkforwarder-<...>-linux-2.6-amd64.deb` for Debian/Ubuntu
  `sudo rpm -i splunkforwarder-<...>linux-2.6-x86_64.rpmm` for RedHat/Centos
3. Change the splunk forwarder password from the default of "changeme"
  `sudo /opt/splunkforwarder/bin/splunk edit user admin -password "<password>"`
4. Configure the forwarder to forward logs to the Splunk collector
  `sudo /opt/splunkforwarder/bin/splunk add forward-server <Splunk Collector IP>:9997`
5. Configure the forwarder to start on boot
  `sudo /opt/splunkforwarder/bin/splunk enable boot-start`
6. Edit the inputs.conf file and put in the hostname at the top of the file.  This file determines what log files to upload to splunk.  
  `sudo vi inputs.conf `
7. Copy the file over to /opt/splunkforwarder/etc/system/local/inputs.conf
  `sudo cp inputs.conf /opt/splunkforwarder/etc/system/local/inputs.conf`
8. Start Splunk
  `sudo service splunk start`



## Message Queue testing
1.  set IFS env. variable
  `IFS=$'\n'`
2.  create file with syslog messages that include (start, residential), iterate over and inject into buffer via netcat
  `for i in ``cat syslog_test.txt``; do sleep 0.01; echo $i | nc -u -q1 172.18.11.211 514 ; done`

## Release History

* 0.0.0
    * Initialization
* 1.0.0
    * Ready for Production

## Meta

Pratik Lotia - plotia@charter.com,
Rich Compton - rcompton@charter.com,
Thomas Bowlby - thomas.bowlby@charter.com

Charter Communications

## Contributing

1. Fork it (<https://github.com/yourname/yourproject/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request