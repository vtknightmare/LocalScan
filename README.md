# LocalScan 

<p align="center">
<img src="https://img.shields.io/badge/Python-2-yellow.svg"> <img src="https://img.shields.io/npm/l/express.svg"></a>

This local scan tool was designed to scan and discover your local network.

## About
Local scan is extensive tool for scanning and discovering local network. For example, you can find your routers, L3 devices, windows machines(development process is still active), path to google in your network, users with ip and mac adresses. In addition to these, you can check what the LocalScan tool did, while it was working thanks to `logs section` in the program. When the program is finished by typing `ctrl-c`, the report about everything that was found by LocalScan tool, will be written as `report.txt` to the file where you launched the LocalScan tool.

## Installation
To install the latest development version type the following commands:

```bash
git clone https://github.com/pioneerhfy/LocalScan # Download the latest revision
cd LocalScan # Switch to tool's directory
sudo pip install -r requirements.txt
sudo pip install python-geoip
sudo pip install python-geoip-geolite2
sudo python LocalScan.py -c <number_of_users> # Just type this command and follow the other steps.
```
## Usage

In order to run this program properly, you have to use PostgreSql database management system. After installing PostgreSql, you should import `localscan.sql` to the postgresql server. Finally you must change `conn = psycopg2.connect(host="localhost", database="localscan", user="postgres", password="*")` line in the localscan.py program with your information.

After the configuration of database, just run `sudo python LocalScan.py -c <number_of_users>` from the terminal and reply questions that is required for LocalScan. If there is no problem in starting program, you'll see banner text in terminal. In order to run this program without any problem, you have to be root user or have root privileges otherwise, you'll encounter annoying socket errors.                         

## Samples

```shell
sudo python localscan.py -c 100

-->Please give local ip adress: 192.168.2.1
-->Please give your subnet in CIDR format(24,16,8,23...etc): 24
-->Is there any problem that might effect arp scan in your local network like (DUP)[y/yes/ok/Y] (default=No): yes

```
## Built With

* [Python 2.7](https://www.python.org/)
* [Scapy 2.3.3](http://www.secdev.org/projects/scapy/) - Used to generate network packets
* [multiprocessing](https://docs.python.org/2/library/multiprocessing.html) - For multiprocessing processes
* [netaddr](https://pypi.python.org/pypi/netaddr) - For IP subnetting
* [python_geoip==1.2](https://pypi.python.org/pypi/python-geoip) - For finding geolocation of IP adress
* [psycopg2==2.7.3.2](https://pypi.python.org/pypi/psycopg2) - For postgresql
* [tabulate==0.7.7](https://pypi.python.org/pypi/tabulate) - For reporting process


## Warning

Just use this tool for education purposes.

<p align="center">
<img src="https://github.com/pioneerhfy/ARPiScan/blob/master/snorlax-black-and-white.png" width="350" height="325">

