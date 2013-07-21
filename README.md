A tool for finding unencrypted network connections.

It sniffs traffic, attempts to reassemble tcp connections, guesses if
the connection is encrypted. Currently it logs all traffic to disk.

Hopes for the future include:
 - scanning the data for things to suggest that a process is up to something
   naughty: email addresses, phone numbers, serials, etc.
 - Only logging "interesting" traffic.

amusing hacks in the codebase include:
 - being lazy about reassembling tcp flows. If the four tuple (src address, dest
   address, src port and dest port) matches, append it to the end of the stream.
   No attempt is made to deal with retries or out of order packets.
 - guessing if a collection of bytes is encrypted by seeing if the mean of them
   is about 127.
