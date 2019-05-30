import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import numpy as np
import csv
import sys


xml = sys.argv[1]
tree = ET.parse(xml) 
root = tree.getroot() 
nmap_hosts = root.findall('host') 

hosts = []
host = {}
explode = []
explode_os = []

protocol_counter = {}
os_counter = {'windows':0, 'linux' : 0}

plt.rcParams['font.size'] = 8.5 #change this if you want bigger/smaller fonts
colors = ["#6c81d9",
"#c19e3d",
"#7e58ad",
"#4cc490",
"#009ec4",
"#719943",
"#b74873",
"#b9553d"]


csv_file = open('scan.csv', 'w')
csv_writer = csv.writer(csv_file)
top_row = ['Ip', 'Host', 'OS', 'Protocol', 'Port', 'Version']
excel_rows = []
csv_writer.writerow(top_row)

for nmap_host in nmap_hosts:
    host["ip_address"] = nmap_host.findall('address')[0].attrib['addr']
    hostnames = nmap_host.findall('hostnames')
    os_list = nmap_host.findall('os')
    port_list = nmap_host.findall('ports')
    
    if not nmap_host.findall('status')[0].attrib['state'] == 'up':
	continue
    try:
        host["hostname"] = hostnames[0].findall('hostname')[0].attrib['name']
    except IndexError:
        host["hostname"] = ''
    
    try:
        host["os"] = os_list[0].findall('osmatch')[0].attrib['name']
        if 'inux' in host["os"]:
            os_counter['linux'] += 1
        elif 'indows' in host["os"]:
            os_counter['windows'] += 1
            
    except IndexError:
        host["os"] = ''

    nmap_ports = port_list[0].findall('port')
    ports = []
    port = {}
    
    for nmap_port in nmap_ports:
	if not nmap_port.findall('state')[0].attrib['state'] == 'open':
	    continue
	else:
            port["port_id"] = nmap_port.attrib['portid']
            port["protocol"] = nmap_port.findall('service')[0].attrib['name']
            
        
        if port["protocol"] not in protocol_counter:
            protocol_counter[port["protocol"]] = 0
            
        protocol_counter[port["protocol"]] += 1        
        
        try:
            port["version"] = nmap_port.findall('service')[0].attrib['product'] + ' ' + nmap_port.findall('service')[0].attrib['version']
        except (IndexError, KeyError):
            port["version"] = ''

	excel_hosts = [host["ip_address"], host["hostname"], host["os"], port["protocol"], port["port_id"], port["version"]]
        csv_writer.writerow(excel_hosts)
        ports.append(port)
        port = {}
    
    host["ports"] = ports
    hosts.append(hosts)
    host = {}
   

 
sorted_protocol = sorted(protocol_counter.items(), key=lambda t: t[1], reverse=True)


plt.figure(figsize=(15,8))
labels = protocol_counter.keys()
sizes = protocol_counter.values()
total = sum(sizes)

for i in range(len(sizes)):
    explode.append(0.1)


def func(pct, allvals):
    absolute = int(pct/100.*np.sum(allvals))
    return "{:.1f}% ({:d} )".format(pct, absolute)


#patches, texts = plt.pie(sizes, colors=colors, shadow=False, startangle=90)
#plt.legend(patches, labels, loc="best")
plt.pie(sizes, labels=labels, autopct=lambda pct: func(pct, (total+1)), colors=colors, explode=explode, startangle=-90)
#plt.pie(sizes, labels=labels, autopct=lambda(p): '{:.0f}'.format(p * total / 100), explode=explode, startangle=-90)


plt.title('Distribution of Services \n')
plt.axis('equal')
plt.tight_layout()
plt.savefig('services.png')

plt.figure(figsize=(15,8))
labels = os_counter.keys()
sizes = os_counter.values()
total = sum(sizes)

for i in range(len(sizes)):
    explode_os.append(0.1)


def func(pct, allvals):
    absolute = int(pct/100.*np.sum(allvals))
    return "{:.1f}% ({:d} )".format(pct, absolute)


#patches, texts = plt.pie(sizes, colors=colors, shadow=True, startangle=90)
#plt.legend(patches, labels, loc="best")
#plt.pie(sizes, labels=labels, autopct=lambda pct: func(pct, (total+1)), colors=colors, explode=explode_os, startangle=-90)
plt.pie(sizes, labels=labels, autopct=lambda(p): '{:.0f}'.format(p * total / 100), explode=explode_os, startangle=-90)

plt.title('Distribution of Operating Systems \n')
plt.axis('equal')
plt.tight_layout()
plt.savefig('os.png')





