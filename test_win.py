#!/usr/bin/python3
# you must install pexpect for this to work:
#	sudo apt-get install python3-pip
#	sudo pip3 install pexpect
import time
import re
import winpexpect
import sys


timeout = 90
msg = 'Hi'
try:
	start = time.time()
	setup = winpexpect.winspawn('py setup.py', timeout=30)
	setup.logfile =  sys.stdout
	setup.expect('>')
	end = time.time()
	print('setup.py done')
	print('time: '+str(end-start))
	peer1 = winpexpect.winspawn('py interactive_peer.py localhost 5566 kris1 5', timeout=timeout)
	peer2 = winpexpect.winspawn('py interactive_peer.py localhost 5656 kris2 5', timeout=timeout)

	peer1.logfile = sys.stdout
	peer2.logfile = sys.stdout
	#setup peer1
	peer1.expect('>')
	peer1.sendline('hello')
	peer1.expect('>')
	peer1.sendline('secret private.pem')
	peer1.expect('>')


	#setup peer2
	peer2.expect('>')
	peer2.sendline('hello')
	peer2.expect('>')
	peer2.sendline('secret private2.pem')
	peer2.expect('>')


	# wait for network to manifest
	time.sleep(3)

	# befriend eachother
	peer1.sendline('friend peer2 public2.pem')
	peer1.expect('>')
	peer2.sendline('friend peer1 public.pem')
	peer2.expect('>')


	start = time.time()
	#send message via flooding
	peer1.sendline('message peer2 '+msg)
	#peer2.expect('Received Message from peer1: '+msg)
	peer1.expect('peer2 received message! \(verified\)')
	end = time.time()
	print('Flooding message success!')
	print('time: '+str(end-start))
	peer1.sendline('mpassed-all')
	peer1.expect('Messages passed by all peers in network: (\d+).*')
	mpassed = re.compile('\d+').search(str(peer1.after)).group()
	print('total messages: '+mpassed)

	start = time.time()
	# send message via k walker
	peer1.sendline('kmessage peer2 '+msg)
	#peer2.expect('Received Message from peer1: '+msg+'.*')
	peer1.expect('Message delivered and acknowledged:.+.*')
	end = time.time()
	print('KWalker message success!')
	print('time: '+str(end-start))

except winpexpect.TIMEOUT as err:
	print('peer1.before: '+str(peer1.before))
	print('peer1.after: '+str(peer1.after))
	print('peer2.before: '+str(peer2.before))
	print('peer2.after: '+str(peer2.after))
	raise err