# Auto-Flowspec Docker Container

## Description
This is a self-contained flowspec controller in a container.  The auto-flowspec.py script will listen for syslog messages from an Arbor SP PI device.  If the syslog message contains "Residential" and "importance 2" (high level alert) (BTW, this is configurable) and doesn't contain "is now done" (indicating that the attack is over) then a API call will be made with Flowspec rules to the flask server which controls ExaBGP.  ExaBGP will then send the rules to one or two route reflectors.  The alert details are also written to a MySQL database.
Once a syslog message saying that the attack "is now done", another API call is made to ExaBGP to remove the rules.  There is also a clean-up script that will remove any rules that have not been withdrawn after a specified amount of time.

## Installation
1. Clone the git repository:
`git clone https://github.com/racompton/docker-auto-flowspec.git`
2. Install docker with the command:
Debian/Ubuntu: `sudo apt install -y docker.io` or RedHat/CentOS: `sudo yum install -y docker.io`
3. Create the docker network with the command:
` sudo docker network create --subnet 192.168.0.0/24 auto-flowspec-net`
4. Edit the Dockerfile to populate the relevant environment variables then build the container with the command: 
`sudo docker build --no-cache -t auto-flowspec .`
5. Then run the container with the command: 
`sudo docker run --name auto-flowspec -v /var/log/auto-flowspec:/var/log/auto-flowspec -d --restart unless-stopped -p 179:179 -p 514:514/udp -p 9001:9001 --net auto-flowspec-net --ip 192.168.0.2 auto-flowspec`
6. Log in to the Supervisor http server with the username of admin and specified password to view the status and STDOUT of the relevant processes at http://<Host IP>:9001
7. You will probably want to configure iptables to allow inbound traffic from ArborSP on UDP port 514, inbound traffic from your route refelectors on TCP port 179 and inbound management traffic on SSH (TCP 22) and TCP 9001 (supervisord management web UI).

## Logroate
The log rotate config files need to be copied over to  /etc/logrotate.d/exabgp-logrotate and /etc/logrotate.d/auto-flowspec-logrotate


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
