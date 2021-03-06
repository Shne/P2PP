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
	start = time.time()
	setup = pexpect.spawn('./setup.py -peers 10', timeout=30)
	setup.expect('>')
	end = time.time()
	print('setup.py done')
	print('time: '+str(end-start))
	peer1 = pexpect.spawn('./interactive_peer.py localhost 8500 peer1 5', timeout=timeout)
	peer2 = pexpect.spawn('./interactive_peer.py localhost 8501 peer2 5', timeout=timeout)

	#setup peer1
	peer1.expect('>')
	peer1.sendline('secret private.pem')
	peer1.expect('>')
	peer1.sendline('hello')
	peer1.expect('>')

	#setup peer2
	peer2.expect('>')
	peer2.sendline('secret private2.pem')
	peer2.expect('>')
	peer2.sendline('hello')
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
	peer2.expect('Received Message from peer1: '+msg+'\r\n')
	peer1.expect('peer2 received message! \(verified\)\r\n')
	end = time.time()
	print('Flooding message success!')
	print('time: '+str(end-start))
	peer1.sendline('mpassed-all')
	peer1.expect('Messages passed by all peers in network: (\d+)\r\n')
	mpassed = re.compile('\d+').search(str(peer1.after)).group()
	print('total messages: '+mpassed)

	start = time.time()
	# send message via k walker
	peer1.sendline('kmessage peer2 '+msg)
	peer2.expect('Received Message from peer1: '+msg+'\r\n')
	peer1.expect('Message delivered and acknowledged:.+\r\n')
	end = time.time()
	print('KWalker message success!')
	print('time: '+str(end-start))

except pexpect.TIMEOUT as err:
	print('peer1.before: '+str(peer1.before))
	print('peer1.after: '+str(peer1.after))
	print('peer2.before: '+str(peer2.before))
	print('peer2.after: '+str(peer2.after))
	raise err