# A basic script to check firewall setup, ssh connectivity,
# fail2ban setup and open ports on a system by utilising
# standard UNIX networking commands

import pprint
import os
import nmap3
import subprocess
import time
import paramiko

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort


class HostMachine:

    def __init__(self, ip_address, student_id):
        self.id = student_id
        self.adr = ip_address
        self.openPorts = []
        self.isLive = False

        # IPTABLES related
        self.blocksICMP = False
        self.blocksFlood = False
        self.blocksXMAS = False

        # SSH related
        self.hasFail2ban = False
        self.hasSSHServer = False

        self.grade = 0

    def updatePorts(self, portid):
        self.openPorts.append(portid)


def ping(host):
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
    nmap_discover = nmap3.NmapHostDiscovery()
    res = nmap_discover.nmap_no_portscan(host.adr)
    host_state = res[host.adr]['state']['state']
    if (host_state == 'down'):
        print("Host is down\n")
        host.isLive = False
    elif (host_state == 'up'):
        print("Host is up\n")


def send_syn(target_ip_address, target_port=22, number_of_packets_to_send=1000, size_of_packet=65000):
    ip = IP(dst=target_ip_address)
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
    raw = Raw(b"X" * size_of_packet)
    p = ip / tcp / raw
    send(p, count=number_of_packets_to_send, verbose=0)
    print('send_syn(): Sent ' + str(number_of_packets_to_send) + ' packets of ' +
          str(size_of_packet) + ' size to ' + target_ip_address + ' on port ' + str(target_port))


def syn_flood(host):

    send_syn(host.adr)
    time.sleep(2)
    discover(host)
    if (host.isLive):
        print("Host {} succesfully blocked flooding attack.".format(host.adr))
        host.blocksFlood = True


def send_XMAS(host):

    XMAS_scan = "nmap " + host.adr + " -sX"
    timeoutSeconds = 1

    try:
        subprocess.check_output(
            XMAS_scan, shell=True, timeout=timeoutSeconds)
    except subprocess.TimeoutExpired:
        host.blocksXMAS = True


def ssh_connect(host):
    # SSH Password login
    # If end users only allow public key logins, then they are automatically stopped by the ssh server from entering
    # Fail2ban mode must be set on aggressive on jail.local for the ssh jail

    username = "debian"
    password = ""

    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host.adr, username=username, password=password)
        _stdin, _stdout, _stderr = client.exec_command("df")
        print(_stdout.read().decode())
    except paramiko.ssh_exception.BadAuthenticationType:
        print("Password logins are not allowed on machine{}.\n".format(host.adr))
    except Exception as e:
        print(e)
    finally:
        client.close()
        host.hasSSHServer = True


def fail2ban_test(host):
    
    for i in range(5):
        ssh_connect(host)
       


def grade(hosts):

    print("Student's grades are:")
    print("---------------------")
    print("AM: \t\tIP address: \tGrade: ")
    for host in hosts:
        ### Firewall ###
        if host.blocksICMP:
            host.grade += 1
        if host.blocksXMAS:
            host.grade += 1
        if host.blocksFlood:
            host.grade += 1
        ### SSH/Fail2Ban ###
        if host.hasSSHServer:
            host.grade += 2
        if host.hasFail2ban:
            host.grade += 3
        if host.isLive:
            host.grade += 1
        else:
            host.grade = 0

        print("{}\t{}\t{}/10".format(host.id, host.adr, host.grade))


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

    print("Host:{}'s open ports are: \n{}\n".format(host.adr, host.openPorts))


def main():

    ### Testing data for my raspberryPi ###
    raspberry = [HostMachine("192.168.1.115", "up1066593")]
    localVMs = [HostMachine("192.168.123.122", "up1066593")]
    hosts = localVMs
    ### Parse the file and create the hosts list ###
    # with open("student_info.csv", "r") as f:

    for host in hosts:
        ### Check the firewall ###
        check_ports(host)
        ping(host)
        syn_flood(host)
        send_XMAS(host)
        ### Check SSH connectivity ###
        ssh_connect(host)
        # fail2ban_test(hosts)

    ### Grade student work ###
    grade(hosts)


if __name__ == "__main__":
    main()
