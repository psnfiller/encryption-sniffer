from scapy import all as scapy
import sys
import os

class State(object):
	def __init__(self):
	  self.four_t = {}
	  self.total_packets = 0
	  self.non_ip_packets = 0
	  self.non_tcp_packets = 0
	def ProcessOnePacket(self, packet):
		self.total_packets += 1
		if not scapy.IP in packet:
			self.non_ip_packets += 1
			return
		if not packet.haslayer(scapy.TCP):
			self.non_tcp_packets += 1
			return
		source_address = packet.getlayer(scapy.IP).src
		destination_addresss = packet.getlayer(scapy.IP).dst
		source_port = packet.getlayer(scapy.TCP).sport
		dest_port = packet.getlayer(scapy.TCP).dport
		key = (source_address, destination_addresss,source_port, dest_port)
		self.four_t.setdefault(key, []).append(packet)

	def __str__(self):
		return """%r
		total packets %r
		non ip packets %r
		non tcp packets %r""" % (self.four_t, self.total_packets, self.non_ip_packets, self.non_tcp_packets)

	def AssembleStreams(self):
		streams_count = 0
		for key in self.four_t:
			streams_count +=1
			source_address, destination_addresss,source_port, dest_port = key
			packets = self.four_t[key]
			packet = packets[0]
			tcp = packet.getlayer(scapy.TCP)
			data_dir = 'data'
			if not os.path.exists(data_dir):
			  os.makedirs(data_dir)
			file_name = 'data/%s_%s_%s_%s' % tuple(map(str, key))
			with open(file_name, 'w') as fh:
				for packet in packets:
					tcp = packet.getlayer(scapy.TCP)
					print dir(tcp)
					payload = tcp.payload
					print type(payload).__name__
					if isinstance(payload, scapy.NoPayload):
						print 'skip'
						continue
					print dir(payload.load)
					fh.write(payload.load)

		print streams_count

def main(argv):
	s = State()
	#scapy.sniff(count=10, prn=s.ProcessOnePacket)
	scapy.sniff(offline="example.pcap", prn=s.ProcessOnePacket)
	s.AssembleStreams()


if __name__ == '__main__':
  main(sys.argv)
