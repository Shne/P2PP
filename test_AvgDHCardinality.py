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
	print('start: {:.2f}'.format(time.time()))
	setup = pexpect.spawn('./setup.py -peers 80 -late 0.1', timeout=30)
	setup.expect('>')
	peer = pexpect.spawn('./interactive_peer.py localhost 8500 peer1 5', timeout=timeout)

	#setup peer1
	peer.expect('>')
	peer.sendline('hello')
	peer.expect('>')

	while True:
		peer.sendline('dhcard-all')
		peer.expect('Average Diffie-Hellman connection pool cardinality in this network: \d+.\d+\r\n')
		avgdhcard = re.compile('\d+.\d+').search(str(peer.after)).group()
		totalTime = '{:.2f}'.format(time.time())
		print(totalTime + ' ' + avgdhcard)

	

except pexpect.TIMEOUT as err:
	print('peer1.before: '+str(peer1.before))
	print('peer1.after: '+str(peer1.after))
	print('peer2.before: '+str(peer2.before))
	print('peer2.after: '+str(peer2.after))
	raise err