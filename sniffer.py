from scapy import all as scapy
import sys
import os
import threading
import time

class BiDiStreamKey(object):
  def __init__(self, source_address, destination_addresss, source_port, dest_port):
    self.source_address = source_address
    self.destination_addresss = destination_addresss
    self.source_port = source_port
    self.dest_port = dest_port

  def __str__(self):
    ports = sorted([self.source_port, self.dest_port])
    addresses = sorted([self.source_address, self.destination_addresss])
    return 'BiDiStreamKey(' + ', '.join(map(str, addresses + ports )) + ')'


  def __repr__(self):
    return self.__str__()

  def __eq__(self, other):
    if (self.source_address ==other.source_address and
        self.destination_addresss == other.destination_addresss and
        self.source_port == other.source_port and
        self.dest_port == other.dest_port):
      return True
    if (self.source_address == other.destination_addresss and
        self.destination_addresss == other.source_address and
        self.source_port == other.dest_port and
        self.dest_port == other.source_port):
      return True
    return False

  def __hash__(self):
    return hash(str(self))

  def reverse(self):
    return BiDiStreamKey(self.destination_addresss, self.source_address, self.dest_port, self.source_port)


class BiDiStream(object):
  def __init__(self, source_address, destination_addresss, source_port, dest_port):
    self.source_address = source_address
    self.destination_addresss = destination_addresss
    self.source_port = source_port
    self.dest_port = dest_port
    self.packets = []

  def append(self, e):
    self.packets.append(e)
  def GetPayloads(self):
    data_stream = bytearray()
    for packet in self.packets:
      payload = packet.getlayer(scapy.TCP).payload
      if isinstance(payload, scapy.NoPayload):
     		continue
      if payload.load:
         data_stream.extend(payload.load)
    return data_stream

  def IsEncrypted(self):
    a = self.GetPayloads()
    x = sum(a) / float(len(a))
    return 125 < x < 130

  def HasPayload(self):
    return len(self.GetPayloads())

  def FourT(self):
    return self.source_address, self.destination_addresss, self.source_port, self.dest_port

  def FourTasStr(self):
    return '_'.join(map(str, (self.source_address, self.destination_addresss, self.source_port, self.dest_port)))

  def DumpToFile(self, directory):
    file_name = '_'.join(map(str, (self.source_address, self.destination_addresss, self.source_port, self.dest_port)))
    path = os.path.join(directory, file_name)
    open(path, 'w').write(self.GetPayloads())


class BiDiStreams(dict):
  def __contains__(self, obj):
    if dict.__contains__(self, obj):
      return True
    r = obj.reverse()
    if dict.__contains__(self, r):
      return True
    return False
  def __getitem__(self, k):
    if dict.__contains__(self, k):
      return dict.__getitem__(self, k)
    r = k.reverse()
    return dict.__getitem__(self, r)

  def __setitem__(self, k, v):
    if dict.__contains__(self, k):
      dict.__setitem__(self, k, v)
    r = k.reverse()
    dict.__setitem__(self, r, v)


class State(object):
  def __init__(self):
    self.total_packets = 0
    self.non_ip_packets = 0
    self.non_tcp_packets = 0
    self.lock = threading.Lock()
    self.in_shutdown = False
    self.in_shutdown_e = threading.Event()
    self.streams = BiDiStreams()

  def AppendToStream(self, source_address, destination_addresss, source_port, dest_port, data):
    key = BiDiStreamKey(source_address, destination_addresss,source_port, dest_port)
    if key in self.streams:
      self.streams[key].append(data)
      return
    self.streams[key] = BiDiStream(source_address, destination_addresss,source_port, dest_port)
    self.streams[key].append(data)

  def ProcessOnePacket(self, packet):
    sys.stdout.write('.')
    sys.stdout.flush()
    self.lock.acquire()
    self.total_packets += 1
    if not scapy.IP in packet:
      self.non_ip_packets += 1
      self.lock.release()
      return
    if not packet.haslayer(scapy.TCP):
      self.non_tcp_packets += 1
      self.lock.release()
      return
    source_address = packet.getlayer(scapy.IP).src
    destination_addresss = packet.getlayer(scapy.IP).dst
    source_port = packet.getlayer(scapy.TCP).sport
    dest_port = packet.getlayer(scapy.TCP).dport
    self.AppendToStream(source_address, destination_addresss,source_port, dest_port, packet)
    self.lock.release()

  def __str__(self):
    return """%r
    total packets %r
    non ip packets %r
    non tcp packets %r""" % (self.four_t, self.total_packets, self.non_ip_packets, self.non_tcp_packets)


  def AssembleStreams(self):
    print '\ncalling AssembleStreams'
    self.lock.acquire()
    streams_count = 0
    connection_is_encrypted = {}
    data_dir = 'data'
    if not os.path.exists(data_dir):
      os.makedirs(data_dir)

    state_dir = os.path.join(data_dir, 'state')
    if not os.path.exists(state_dir):
      os.makedirs(state_dir)
    state_path = os.path.join(state_dir, str(time.time()))
    with open(state_path, 'w') as state_fh:
      for stream in self.streams.itervalues():
        stream.DumpToFile(data_dir)
        if stream.HasPayload():
          state_fh.write('%s %s\n' % (stream.FourTasStr(), stream.IsEncrypted()))
    self.lock.release()

  def LoopOnAssembleStreams(self):
    while True:
      print 'self.in_shutdown.wait'
      if self.in_shutdown or self.in_shutdown_e.wait(30):
        print 'self.in_shutdown.is_set'
        break
      self.AssembleStreams()
      print 'g'
    print 'finished LoopOnAssembleStreams'

  def Shutdown(self):
    print 'in Shutdown'
    self.in_shutdown = True
    self.in_shutdown_e.set()
    print self.in_shutdown_e

def main(argv):
  if len(argv) > 1:
    file_name = argv[1]
  else:
    file_name = None
  s = State()
  t = threading.Thread(target=s.LoopOnAssembleStreams)
  t.start()

  try:
    if file_name is None:
      scapy.sniff(count=100000, prn=s.ProcessOnePacket)
    else:
      scapy.sniff(offline=file_name, prn=s.ProcessOnePacket)
  except (KeyboardInterrupt, ) as e:
    print 'Exception'
    print e
    s.Shutdown()
  s.AssembleStreams()


if __name__ == '__main__':
  main(sys.argv)
