from scapy import all as scapy
import sys
import os
import threading
import time

class State(object):
  def __init__(self):
    self.four_t = {}
    self.total_packets = 0
    self.non_ip_packets = 0
    self.non_tcp_packets = 0
    self.lock = threading.Lock()
    self.in_shutdown = False
    self.in_shutdown_e = threading.Event()

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
    key = (source_address, destination_addresss,source_port, dest_port)
    self.four_t.setdefault(key, []).append(packet)
    self.lock.release()

  def __str__(self):
    return """%r
    total packets %r
    non ip packets %r
    non tcp packets %r""" % (self.four_t, self.total_packets, self.non_ip_packets, self.non_tcp_packets)

  def IsEncrypted(self, data_stream):
    x = sum(data_stream) / float(len(data_stream))
    return 125 < x < 130

  def AssembleStreams(self):
    print '\ncalling AssembleStreams'
    self.lock.acquire()
    streams_count = 0
    connection_state = {}
    data_dir = 'data'
    if not os.path.exists(data_dir):
      os.makedirs(data_dir)
    for key in self.four_t:
      streams_count +=1
      source_address, destination_addresss,source_port, dest_port = key
      packets = self.four_t[key]
      data = []
      for packet in packets:
      	tcp = packet.getlayer(scapy.TCP)
      	payload = tcp.payload
      	if isinstance(payload, scapy.NoPayload):
      		continue
      	if payload.load:
      		data.append(payload.load)
      if not data:
      	continue
      data_stream = bytearray()
      for d in data:
        for x in d:
          data_stream.append(x)

      connection_state[key] = self.IsEncrypted(data_stream)
      file_name = 'data/%s_%s_%s_%s' % tuple(map(str, key))
      with open(file_name, 'w') as fh:
      	fh.write(''.join(data))

    state_dir = os.path.join(data_dir, 'state')
    if not os.path.exists(state_dir):
      os.makedirs(state_dir)
    with open(os.path.join(state_dir, str(time.time())), 'w') as fh:
      for key, v in connection_state.iteritems():
        fh.write('%s %r\n' % (' '.join(map(str, key)), v))

    print streams_count
    print 'done in AssembleStreams'
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

def main(argv):
  if len(argv) > 1:
    file_name = argv[1]
  else:
    file_name = None
  s = State()
  t = threading.Thread(target=s.LoopOnAssembleStreams)
  t.daemon = True
  t.start()

  try:
    if file_name is None:
      scapy.sniff(count=100000, prn=s.ProcessOnePacket)
    else:
      scapy.sniff(offline=file_name, prn=s.ProcessOnePacket)
  except Exception as e:
    print 'Exception'
    print e
    s.Shutdown()
  s.AssembleStreams()



if __name__ == '__main__':
  main(sys.argv)
