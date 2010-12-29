#!/usr/bin/env python

from scapy.all import *
import socket

class XboxProxy(object):
  LOCAL = 1

  def __init__(self):
    self.server_port = 6767
    self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.udp.bind(("0.0.0.0", self.server_port))

    self.cam_table = dict()
  # def __init__

  def add_to_cam(self, identity, location):
    if identity not in self.cam_table:
      print "New identity known: %s at %s" % (identity, location)
      self.cam_table[identity] = location

  # Get packet
  #   If local, set local in cam
  #   Else, set ether -> proxy ip in cam
  #   
  #   If ether dst is broadcast, broadcast
  #   Else, look up target in cam.
  def packet(self, p):
    if p[IP].src == "0.0.0.1":
      location = "local"
    else:
      location = "%s:%s" % (p[IP].src, p[UDP].sport)
      try:
        p = Ether(str(p[UDP].payload))
      except Exception as e:
        print "Invalid packet from %s:%d" % (p[IP].src, p[UDP].sport)
        return
    # Have location, now get the identity

    identity = p[Ether].src
    self.add_to_cam(identity, location)

    # Push the packet.
    ether_dest = p[Ether].dst
    if ether_dest == "ff:ff:ff:ff:ff:ff":
      for cam_id, cam_loc in self.cam_table.iteritems():
        if location == cam_loc:
          continue
        self.sendto(p, cam_loc)
    else:
      # look up destination mac in cam table
      # send to that
      if ether_dest in self.cam_table:
        self.sendto(p, self.cam_table[ether_dest])
      else:
        print "Unicast to '%s' failed, not known in CAM table" % ether_dest

    return
  # def packet

  def sendto(self, p, destination):
    print "Sending to %s: %r" % (destination, p)
    if destination == "local":
      send(p)
    else:
      host, port = destination.split(":")
      
      print repr([str(p), (host, int(port))])
      self.udp.sendto(str(p), (host, int(port)))

  def run(self):
    sniff(filter="host 0.0.0.1 or (udp and dst port %d)" % self.server_port,
          prn=self.packet)
  # def run

# class XboxProxy

XboxProxy().run()
