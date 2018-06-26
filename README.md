# Auto-Flowspec Docker Container

## Description
This is a self-contained flowspec controller in a container.  The auto-flowspec.py script will listen for syslog messages from an Arbor SP PI device.  If the syslog message contains "Residential" and "importance 2" (high level alert) and doesn't contain "is now done" (attack is over) then a API call will be made with Flowspec rules to a flask server which controls ExaBGP.  ExaBGP will then send the rules to one or two route reflectors.  The alert details are also written to a MySQL database.
Once a syslog message saying that the attack "is now done", another API call is made to ExaBGP to remove the rules.  There is also a clean-up script that will remove any rules that have not been withdrawn after a specified amount of time.

## Installation
1. Clone the git repository:
`git clone https://github.com/racompton/docker-auto-flowspec.git`
2. Install docker with the command:
`sudo apt install -y docker.io` or `sudo yum install -y docker.io`
3. Create the docker network with the command:
` sudo docker network create --subnet 192.168.0.0/24 auto-flowspec-net`
4. Edit the Dockerfile to populate the relevant environment variables then build the container with the command: 
`sudo docker build sudo docker --no-cache -t auto-flowspec .`
5. Then run the container with the command: 
`sudo docker run --name auto-flowspec -v /var/log/auto-flowspec:/var/log/auto-flowspec -d --restart unless-stopped -p 179:179 -p 514:514/udp -p 9001:9001 --net auto-flowspec-net --ip 192.168.0.2 auto-flowspec`

##Logroate
The log rotate config files need to be copied over to  /etc/logrotate.d/exabgp-logrotate and /etc/logrotate.d/auto-flowspec-logrotate

## Message Queue testing
1.  set IFS env. variable
  `IFS=$'\n'`
2.  create file with syslog messages that include (start, residential), iterate over and inject into buffer via netcat
  `for i in ``cat syslog_test.txt``; do sleep 0.01; echo $i | nc -u -q1 <IP of host> 514 ; done`

## Release History

* 0.0.0
    * Initialization
* 1.0.0
    * Ready for Production

## Meta

Pratik Lotia - pratik.lotia@charter.com,
Rich Compton - rich.compton@charter.com,
Thomas Bowlby - thomas.bowlby@charter.com

Charter Communications

## Contributing

1. Fork it (<https://github.com/yourname/yourproject/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
