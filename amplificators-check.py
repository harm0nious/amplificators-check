import sys
import socket
import os
import subprocess
import dns
import requests 
from dns import resolver
from pymemcache.client import base
from pysnmp.hlapi import *


def scanSSDP(file):
  msg = [
  'M-SEARCH * HTTP/1.1',
  'Host:239.255.255.250:1900',
  'ST:upnp:rootdevice',
  'Man:"ssdp:discover"',
  'MX:1',
  '']
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  s.settimeout(1) 
  with open(file) as opennedFile:
    for line in opennedFile:
      s.sendto('\r\n'.join(msg).encode(), (line, 1900) )
      aberto = 0
      while True:
        try:
          data, addr = s.recvfrom(32*1024)
        except socket.timeout:
          break
        aberto = 1
        print(line.replace('\n','') + ';Open')
      if (aberto == 0):
        print(line.replace('\n','') + ';Closed')


def scanDNS(file):
 with open(file) as opennedFile:
  for line in opennedFile:
   resolver = dns.resolver.Resolver()
   resolver.timeout = 1
   resolver.lifetime = 1
   resolver.port = 53
   resolver.nameservers=[line.rstrip('\r\n')]
   try:
    for rdata in resolver.query('www.yahoo.com', 'CNAME') :
     if rdata.target != "":
      print(line.replace('\n','')+';Open')
     else:
      print(line.replace('\n','')+';Closed')
   except:
    print(line.replace('\n','')+';Closed')


def scanmDNS(file):
 with open(file) as opennedFile:
  for line in opennedFile:
   resolver = dns.resolver.Resolver()
   resolver.timeout = 1
   resolver.lifetime = 1
   resolver.port = 5353
   resolver.nameservers=[line.rstrip('\r\n')]
   try:
    oi = resolver.query('_services._dns-sd._udp.local', 'ptr')
    if oi != "":
     print(line.replace('\n','')+';Open')
    else:
     print(line.replace('\n','')+';Closed')
   except:
    print(line.replace('\n','')+';Closed')


def scanMemcached(file):
 with open(file) as opennedFile:
  for line in opennedFile:
   try:
    client = base.Client((line, 11211),connect_timeout=1)
    result = client.set('some_key', 'some value')
    if result == True:
     print(line.replace('\n','')+';Open')
    else:
     print(line.replace('\n','')+';Closed')
   except:
    print(line.replace('\n','')+';Closed')


def scanTFTP(file):
  with open(file) as opennedFile:
    for line in opennedFile:
     with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
      s.settimeout(1)
      message = b''
      addr = (line, 69)
      s.sendto(message, addr)
      try: 
       data, address = s.recvfrom(1024)
       if "Illegal operation" in data.decode():
        print(line.replace('\n','') + ';Open')
       else:
        print(line.replace('\n','') + ';Closed')
      except socket.timeout:
       print(line.replace('\n','') + ';Closed')


def scanLDAP(file):
 with open(file) as opennedFile:
  for line in opennedFile:
   cmd = ['ldapsearch', '-x', '-h', line, '-s', 'base']
   try:
    result = subprocess.run(cmd, timeout=0.5, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if "numResponses" in result.stdout.decode():
     print(line.replace('\n','')+';Aberto')
   except:
    print(line.replace('\n','')+';Closed')


def scanSNMP(file):
  with open(file) as opennedFile:
   for line in opennedFile:
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData('public', mpModel=0),
               UdpTransportTarget((line, 161),timeout=0.5, retries=0),
               ContextData(),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
    )
    try:
     if errorIndication or errorIndex or errorStatus:
        print(line.replace('\n','') + ';Fechado')
     else:
        for varBind in varBinds:
            print(line.replace('\n','') + ';Aberto')
    except:
          print(line.replace('\n','') + ';Fechado')


def scanNTP(file):
  with open(file) as opennedFile:
   for line in opennedFile:
    cmd = ['ntpq', '-c', 'rv', line]
    cmd2 = ['ntpdc', '-n', '-c', 'monlist', line]
    try:
     result = subprocess.run(cmd, timeout=0.5, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
     if result.stdout.decode() != "":
      rv='Open'
     else:
      rv='Closed'
    except:
         rv='Closed'

    try:
     result2 = subprocess.run(cmd2, timeout=0.5, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
     if result2.stdout.decode() != "":
      monlist='Open'
     else:
      monlist='Closed'
    except:
         monlist='Closed'

    if (rv or monlist) != 'Closed':
     print(line.replace('\n','') + ';Open')
    else:
     print(line.replace('\n','') + ';Closed')


def scanNetBIOS(file):
  with open(file) as opennedFile:
    for line in opennedFile:
      result = subprocess.run(['timeout', '1', 'nmblookup', '-A', line], stdout=subprocess.PIPE)
      if result.stdout.decode().find("Address") == -1:
        print(line.replace('\n','')+';Closed')
      else:
        print(line.replace('\n','')+';Open')


def scanPortmap(file):
  with open(file) as opennedFile:
    for line in opennedFile:
      cmd = ['rpcinfo', '-T', 'udp', '-p', line]
      try:
       result = subprocess.run(cmd, timeout=0.5, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       if "service" in result.stdout.decode():
        print(line.replace('\n','') + ';Open')
      except:
       print(line.replace('\n','') + ';Closed')


def scanCHARGEN(file):
  with open(file) as opennedFile:
    for line in opennedFile:
     with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
      s.settimeout(1)
      message = b''
      addr = (line, 19)
      s.sendto(message, addr)
      try: 
       data, address = s.recvfrom(1024)
       if data.decode() != "":
        print(line.replace('\n','') + ';Open')
       else:
        print(line.replace('\n','') + ';Closed')
      except socket.timeout:
       print(line.replace('\n','') + ';Closed')


def scanQOTD(file):
  with open(file) as opennedFile:
    for line in opennedFile:
     with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
      s.settimeout(1)
      message = b''
      addr = (line, 17)
      s.sendto(message, addr)
      try: 
       data, address = s.recvfrom(1024)
       if data.decode() != "":
        print(line.replace('\n','') + ';Open')
       else:
        print(line.replace('\n','') + ';Closed')
      except socket.timeout:
       print(line.replace('\n','') + ';Closed')


#Verify number of arguments
if len(sys.argv) > 1: 

  #Argument HELP
  if ("--help" in str(sys.argv[1]) or (str(sys.argv[1]) == "-h")):
    print ("Usage: amplificators-check.py [OPTION] [FILE]")
    print ("  -h, --help                     	         Show this menu"                    )
    print ("  --scan-QOTD <file>, -qotd <file>           Check for QOTD amplificators"      )
    print ("  --scan-CHARGEN <file>, -chargen <file>     Check for CHARGEN amplificators"   )
    print ("  --scan-DNS <file>, -dns <file>             Check for DNS amplificators"       )
    print ("  --scan-Portmap <file>, -portmap <file>     Check for Portmap amplificators"   )
    print ("  --scan-NTP <file>, -ntp <file>             Check for NTP amplificators"       )
    print ("  --scan-NetBIOS <file>, -netbios <file>     Check for NetBIOS amplificators"   )
    print ("  --scan-SNMP <file>, -snmp <file>           Check for SNMP amplificators"      )
    print ("  --scan-LDAP <file>, -ldap <file>           Check for LDAP amplificators"      )
    print ("  --scan-SSDP <file>, -ssdp <file>           Check for SSDP amplificators"      )
    print ("  --scan-mDNS <file>, -mdns <file>           Check for mDNS amplificators"      )
    print ("  --scan-Memcached <file>, -memcached <file> Check for Memcached amplificators" )
    print ("  --scan-TFTP <file>, -tftp <file>           Check for TFTP amplificators"      )

  
  elif (str(sys.argv[1]) == "--scan-SSDP") or (str(sys.argv[1]) == "-ssdp"):
    if str(sys.argv[2]):     
      scanSSDP(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-DNS") or (str(sys.argv[1]) == "-dns"):
    if str(sys.argv[2]):     
      scanDNS(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-mDNS") or (str(sys.argv[1]) == "-mdns"):
    if str(sys.argv[2]):     
      scanmDNS(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-Memcached") or (str(sys.argv[1]) == "-memcached"):
    if str(sys.argv[2]):     
      scanMemcached(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-TFTP") or (str(sys.argv[1]) == "-tftp"):
    if str(sys.argv[2]):     
      scanTFTP(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-LDAP") or (str(sys.argv[1]) == "-ldap"):
    if str(sys.argv[2]):     
      scanLDAP(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-SNMP") or (str(sys.argv[1]) == "-snmp"):
    if str(sys.argv[2]):     
      scanSNMP(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-NetBIOS") or (str(sys.argv[1]) == "-netbios"):
    if str(sys.argv[2]):     
      scanNetBIOS(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-NTP") or (str(sys.argv[1]) == "-ntp"):
    if str(sys.argv[2]):     
      scanNTP(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-Portmap") or (str(sys.argv[1]) == "-portmap"):
    if str(sys.argv[2]):     
      scanPortmap(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-CHARGEN") or (str(sys.argv[1]) == "-chargen"):
    if str(sys.argv[2]):     
      scanCHARGEN(str(sys.argv[2]))


  elif (str(sys.argv[1]) == "--scan-QOTD") or (str(sys.argv[1]) == "-qotd"):
    if str(sys.argv[2]):     
      scanQOTD(str(sys.argv[2]))
