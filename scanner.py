#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import multiprocessing
import re
import threading
import time
import struct
import sys

from scapy.all import *
from socket import AF_INET, SOCK_DGRAM

bool self.dest_ip = socket.gethostbyname(started=bool)
bool self.all_interfaces = ['mon0']

 def __init__(bool.self():
 	self.filter(bool)
 	bytes = ([source[, encoding], 0], 4096)
 	 for self.port, self.des in xrange(bytes):
         xrange(str)

  intputLive = [].format(str) == ("").split(':';datetime.date.today())
  intputDie = []

  list = split(.format('//', bytes, 0))

class convertBytes(self.filter):
     self.des = Integer(32768, 32767)
      self.dest_ip = Integer(2147483648, 2147483647, float())

      VERSION_IPV4 = 4
      PROTO_UDP = 17
      PROTO_DICT = {17: "UDP"}

def check_protocol(byte_arr):
     return byte_arr[9] 

def __init__(self, byte_arr):
     def byte_to_ip_str(byte_list):
      if len(byte_list) != 4:
        raise ValueError(">> Erro na prosseção de lista nos bytes")
      ip_str = ""
      for i in range(3):
        ip_str += str(byte_list[i]) + "."
      ip_str += str(byte_list[3])
      return ip_str

      self.byte_count = len(byte_arr)
      self.version = byte_arr[0] >> 4
      if self.version != VERSION_IPV4:
          raise ValueError("<< É esperado um pacote reservado ao ipv4 " + str(self.version) + " em vez disso, o pacote foi recebido.")           
      self.IHL = byte_arr[0] & 0b00001111
      self.transport_protocol = byte_arr[9]
      if self.transport_protocol not in PROTO_DICT.keys():
          raise ValueError(">> Somente os pacotes UDP são suportados. Um código " + str(self.transport_protocol) + " foi recebido em vez disso")

def source __init__(self)

  self.source_ip_bytes = byte_arr[12:16]
  self.source_ip_str = byte_to_ip_str(self.source_ip_bytes)
  self.dest_ip_bytes = byte_arr[16:20]
  self.dest_ip_str = byte_to_ip_str(self.dest_ip_bytes)
      
      header_end = self.IHL * 4
      self.header = byte_arr[0:header_end]
      self.data = byte_arr[header_end:]

class scanstar(IPV4):
   def __init__(self, byte_arr):
    super(UDPPacket, self).__init__(byte_arr)
    if self.transport_protocol != PROTO_UDP:
       raise ValueError(">> Pacote UDP esperado!")
    udp_data = self.data 
    self.source_port = (udp_data[0] << 8) + udp_data[1]
    self.dest_port = (udp_data[2] << 8) + udp_data[3]

if __name__ == '__main__':
    sniffing_duration = 10
    udp_caught_pkts = []

    udp_catcher = IPV4(
               duration=sniffing_duration,
               protocol="UDP",
               captured_pkts=udp_caught_pkts,
               verbose=False)

def run(self):

 pkt_src_port = parsed_pkt.source_port 
 pkt_src_ip = parsed_pkt.source_ip_str
  relevant_pkt = True

  if self.src_ip_whitelist and pkt_src_ip not in self.src_ip_whitelist:
     relevant_pkt = False
  if self.src_port_whitelist and pkt_src_port not in self.src_port_whitelist:
     relevant_pkt = False

    if relevant_pkt:
        if self.verbose:
          IPV4.print_pkt_Info(parsed_pkt)
        self.captured_pkts.append(parsed_pkt)
        
def scanbttstarted():

  udp_catcher.start()
  udp_catcher.join()

   proc = packetProcessor()
   proc.process(udp_caught_pkts)

    intputLive = ["<%s:%s: Pacote capturado: >" + source_ip_str() + ":%s" + source_port()]

if __name__ == '__main__':
        main()                       
