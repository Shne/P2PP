#!/usr/bin/python3
# you must install pexpect for this to work:
#	sudo apt-get install python3-pip
#	sudo pip3 install pexpect
import time
import winpexpect
import re
import sys

timeout = 900
msg = 'plplplplplp'
try:
	print('start: {:.2f}'.format(time.time()))
	setup = winpexpect.winspawn('py setup.py -peers 149 -late 0.1', timeout=30)
	setup.logfile =  sys.stdout
	setup.expect('>')
	peer = winpexpect.winspawn('py interactive_peer.py localhost 8500 peer1 5', timeout=timeout)
	#setup peer1
	peer.expect('>')
	peer.sendline('hello')
	peer.expect('>')

	time.sleep(120.0)
	peer.sendline('dhcard-all')
	peer.expect('Average Diffie-Hellman connection pool cardinality in this network: \d+.\d+\r\n')
	avgdhcard = re.compile('\d+.\d+').search(str(peer.after)).group()
	totalTime = '{:.2f}'.format(time.time())
	print(totalTime + ' ' + avgdhcard)

	setup.terminate()
	peer.terminate()

	print('\7')

except winpexpect.TIMEOUT as err:
	print('peer1.before: '+str(peer1.before))
	print('peer1.after: '+str(peer1.after))
	print('peer2.before: '+str(peer2.before))
	print('peer2.after: '+str(peer2.after))
	raise err