#!/usr/bin/python3
# you must install pexpect for this to work:
#	sudo apt-get install python3-pip
#	sudo pip3 install pexpect
import time
import pexpect
import re

timeout = 90
msg = 'plplplplplp'
try:
	setup = pexpect.spawn('./setup.py -peers 40 -late 0.2', timeout=30)
	setup.expect('>')
	peer = pexpect.spawn('./interactive_peer.py localhost 8500 peer1 5', timeout=timeout)

	#setup peer1
	peer.expect('>')
	peer.sendline('hello')
	peer.expect('>')

	start = time.time()

	while True:
		peer.sendline('nadded-all')
		peer.expect('# of neighbours added by all peers in network: \d+\r\n')
		nadded = re.compile('\d+').search(str(peer.after)).group()
		totalTime = '{:.2f}'.format(time.time())
		print(totalTime + ' ' + nadded)

	

except pexpect.TIMEOUT as err:
	print('peer1.before: '+str(peer1.before))
	print('peer1.after: '+str(peer1.after))
	print('peer2.before: '+str(peer2.before))
	print('peer2.after: '+str(peer2.after))
	raise err