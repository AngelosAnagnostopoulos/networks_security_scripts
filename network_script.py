# A basic script to check firewall setup, ssh connectivity,
# and open ports on a system

import pprint
import os
import nmap3
import subprocess
import time
import paramiko
import re
import pydig

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort


class HostMachine:

    def __init__(self, ip_address, student_id):
        self.id = student_id
        self.adr = ip_address
        self.openPorts = []
        self.grade = 1
        self.isLive = False

        # IPTABLES related
        self.blocksICMP = False
        self.blocksFlood = False
        self.blocksXMAS = False

        # SSH related
        self.has22Open = False
        self.blocksPass = False
        self.hasFail2ban = False

        # DNS related
        self.hasBind9 = False
        self.isDNS = False

    def updatePorts(self, portid):
        self.openPorts.append(portid)


def ping(host):
    # Basic ping command

    ping = "ping -c 1 " + host.adr
    timeoutSeconds = 2
    try:
        subprocess.check_output(
            ping, shell=True, timeout=timeoutSeconds)
    except subprocess.TimeoutExpired:
        host.blocksICMP = True
        print("Host does not seem to receive ICMP echo packages.")
    except subprocess.CalledProcessError as err:
        print(err)


def discover(host):
    # Look for hosts and monitor their state

    nmap_discover = nmap3.NmapHostDiscovery()
    res = nmap_discover.nmap_no_portscan(host.adr)
    host_state = res[host.adr]['state']['state']
    if (host_state == 'down'):
        print("Host is down\n")
        host.isLive = False
    elif (host_state == 'up'):
        print("Host is up\n")


def send_syn(target_ip_address, target_port=22, number_of_packets_to_send=1000, size_of_packet=65000):
    # Attempt syn flood attack of host
    ip = IP(dst=target_ip_address)
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
    raw = Raw(b"X" * size_of_packet)
    p = ip / tcp / raw
    send(p, count=number_of_packets_to_send, verbose=0)
    print('send_syn(): Sent ' + str(number_of_packets_to_send) + ' packets of ' +
          str(size_of_packet) + ' size to ' + target_ip_address + ' on port ' + str(target_port))


def syn_flood(host):
    # Try and syn flood attack a host (needs more work)

    send_syn(host.adr)
    time.sleep(2)
    discover(host)
    if (host.isLive):
        print("Host {} succesfully blocked flooding attack.".format(host.adr))
        host.blocksFlood = True


def send_XMAS(host):
    # Send christmas packets with nmap (requires sudo)

    XMAS_scan = "nmap " + host.adr + " -sX"
    timeoutSeconds = 1

    try:
        subprocess.check_output(
            XMAS_scan, shell=True, timeout=timeoutSeconds)
    except subprocess.TimeoutExpired:
        host.blocksXMAS = True


def ssh_connect(host):
    # SSH Password login and exception magic for Fail2Ban detection

    username = "debian"
    password = "le_mao"

    client = paramiko.client.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host.adr, username=username, password=password)
        _stdin, _stdout, _stderr = client.exec_command("df")
        print(_stdout.read().decode())
    except Exception as e:
        if "failed" in e.args[-1]:
            print("Wrong password entered.")
        elif (host.blocksPass and host.has22Open and ("Unable to connect to port" in e.args[-1])):
            print("Fail2Ban blocked us.")
            host.hasFail2ban = True
        elif (host.blocksPass and "timeout" in e.args[0]):
            print("Fail2Ban blocked us.")
            host.hasFail2ban = True
        elif "publickey" in e.args[-1] and (not "password" in e.args[-1]):
            print("Password login disabled, try with the appropriate key.")
            host.blocksPass = True

    finally:
        client.close()


def fail2ban_check(host):
    for _ in range(10):
        time.sleep(0.5)
        ssh_connect(host)

    time.sleep(5)
    ssh_connect(host)


def check_ports(host):
    nmap = nmap3.Nmap()

    res = nmap.scan_top_ports(host.adr, args="-sV -nP")
    host_state = res[host.adr]['state']['state']
    if (host_state == 'up'):
        host.isLive = True

    ports_dict = res[host.adr]['ports']
    for i in range(0, len(ports_dict)):
        if (ports_dict[i]['state'] == 'open'):
            host.updatePorts(ports_dict[i]['portid'])

    if '22' in host.openPorts:
        host.has22Open = True

    print("Host:{}'s open ports are: \n{}\n".format(host.adr, host.openPorts))


def check_dns(host):
    # Check if dig command with @host returns an A record output for the example.com domain, different than the original 93.184.216.34
    dig = "dig @" + host.adr + " example.com"
    regex = r"\d+.\d+.\d+.\d+"
    try:
        p = subprocess.check_output(dig, universal_newlines=True, shell=True)
        p = str.split(p, ";")
        for field in p:
            if "ANSWER SECTION" in field:
                address = re.findall(regex, field)[0]
                if address != "93.184.216.34":
                    host.isDNS = True

    except Exception as e:
        print(e)


def grade(hosts):

    print("Student's grades are:")
    print("---------------------")
    print("AM: \t\tIP address: \tGrade: ")
    for host in hosts:
        ### Firewall ###
        if host.blocksICMP:
            host.grade += 0.5
        if host.blocksXMAS:
            host.grade += 0.5
        if host.blocksFlood:
            host.grade += 0.5
        ### SSH ###
        if host.blocksPass:
            host.grade += 0.5
        if host.hasFail2ban:
            host.grade += 3
        if host.isDNS:
            host.grade += 4
        if not host.isLive:
            host.grade = 0

        print("{}\t{}\t{}/10".format(host.id, host.adr, host.grade))


def main():

    hosts = []

    # Match all IPs and up IDs on file
    regex = r"([0-9.]+),([a-zA-Z]+[0-9]+)"

    # File format: <IP>,<up123456789>\n
    with open("servers.txt", "r") as f:
        Lines = f.readlines()
        for line in Lines:
            matches = re.findall(regex, line)
            hosts.append(HostMachine(matches[0][0], matches[0][1]))

    for host in hosts:
        check_ports(host)
        ping(host)
        syn_flood(host)
        send_XMAS(host)
        ssh_connect(host)
        fail2ban_check(host)
        check_dns(host)

    grade(hosts)


if __name__ == "__main__":
    main()
