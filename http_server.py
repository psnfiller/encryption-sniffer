
from scapy import all as scapy
import sniffer
import sys
import BaseHTTPServer
import threading

HTML_HEADER = """
<html><head><title>Title goes here.</title></head>
<body>
<table>
"""


ROW = """<tr><td>%s</td><td>%s</td></tr>\n"""
HTML_FOOTER = """
</table>
</body>
</html>
"""


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
  def __init__(self,  *args):
    BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args)

  def do_HEAD(s):
    s.send_response(200)
    s.send_header("Content-type", "text/html")
    s.end_headers()

  def do_GET(self):
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.end_headers()
    self.wfile.write(HTML_HEADER)

    for stream in sorted(self.state.streams.itervalues()):
      if stream.HasPayload():
        self.wfile.write(ROW % tuple(
          [stream.FourTasStr()] + [stream.IsEncrypted()]))

    self.wfile.write(HTML_FOOTER)






HOST_NAME = 'localhost'
PORT_NUMBER = 8080
def start_server(state):
  print 'start_server'
  Handler.state = state
  httpd = BaseHTTPServer.HTTPServer((HOST_NAME, PORT_NUMBER), Handler)
  print 'http://%s:%d/' % (HOST_NAME, PORT_NUMBER)
  httpd.serve_forever()

def main(argv):
  if len(argv) > 1:
    file_name = argv[1]
  else:
    file_name = None
  s = sniffer.State()
  t = threading.Thread(target=s.LoopOnAssembleStreams)
  t.start()
  t = threading.Thread(target=start_server, args=(s,))
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
