import unittest
import sniffer

class BiDiStreamKeyTest(unittest.TestCase):
  def testEq(self):
    a = sniffer.BiDiStreamKey('1.1.1.1', '2.2.2.2', 5, 7)
    b = sniffer.BiDiStreamKey('1.1.1.1', '2.2.2.2', 5, 7)
    self.assert_(a == b)

  def testReEq(self):
    a = sniffer.BiDiStreamKey('1.1.1.1', '2.2.2.2', 5, 7)
    b = sniffer.BiDiStreamKey('2.2.2.2', '1.1.1.1', 7, 5)
    self.assert_(a == b)

  def testReverse(self):
    a = sniffer.BiDiStreamKey('1.1.1.1', '2.2.2.2', 5, 7)
    b = a.reverse()
    self.assert_(a == b)

  def testHashReverse(self):
    a = sniffer.BiDiStreamKey('1.1.1.1', '2.2.2.2', 5, 7)
    b = a.reverse()
    self.assert_(hash(a) == hash(b))


class BiDiStreamsTest(unittest.TestCase):
  def testEq(self):
    a = sniffer.BiDiStreams()
    key1 = sniffer.BiDiStreamKey('1.1.1.1', '2.2.2.2', 5, 7)
    self.assertNotIn(key1, a)
    a[key1] = sniffer.BiDiStream('1.1.1.1', '2.2.2.2', 5, 7)
    self.assertIn(key1, a)
    r = key1.reverse()
    self.assertIn(r, a)

  def testLookup(self):
    a = sniffer.BiDiStreams()
    key1 = sniffer.BiDiStreamKey('1.1.1.1', '2.2.2.2', 5, 7)
    v = sniffer.BiDiStream('1.1.1.1', '2.2.2.2', 5, 7)
    self.assertNotIn(key1, a)
    a[key1] = v
    self.assertEqual(a[key1], v)
    self.assertEqual(a[key1.reverse()], v)






if __name__ == '__main__':
      unittest.main()
