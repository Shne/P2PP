#!/usr/bin/python3
# you must install pexpect for this to work:
#	sudo apt-get install python3-pip
#	sudo pip3 install pexpect
import time
import pexpect
import re

timeout = 420
baseMsg = 'plplplplplp'
messages = 10
try:
	start = time.time()
	setup = pexpect.spawn('./setup.py -peers 100', timeout=90)
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
	print('waiting 20 seconds for network to form')
	time.sleep(20)

	# befriend eachother
	peer1.sendline('friend peer2 public2.pem')
	peer1.expect('>')
	peer2.sendline('friend peer1 public.pem')
	peer2.expect('>')

	print('starting flooding test')

	# FLOODING
	# start = time.time()
	# for i in range(messages):
	# 	msg = baseMsg+str(i)
	# 	peer1.sendline('message peer2 '+msg)
	# 	peer2.expect('Received Message from peer1: '+msg+'\r\n')
	# 	print('msg received')
	# 	peer1.expect('peer2 received message! \(verified\)\r\n')	
	# 	print('msg verified')
	# end = time.time()
	# print('Flooding test done!')
	# print('time: '+str(end-start))
	# peer1.sendline('mpassed-all')
	# peer1.expect('Messages passed by all peers in network: (\d+)\r\n')
	# mpassed = re.compile('\d+').search(str(peer1.after)).group()
	# print('total messages: '+mpassed)

	#reset for next test
	peer1.sendline('fullreset-all')
	peer1.expect('>')

	# K WALKER
	start = time.time()
	for i in range(messages):
		msg = baseMsg+str(i)
		peer1.sendline('kmessage peer2 '+msg)
		peer2.expect('Received Message from peer1: '+msg+'\r\n')
		print('msg received')
		peer1.expect('Message delivered and acknowledged:.+\r\n')
		print('msg verified')
	end = time.time()
	print('KWalker test done!')
	print('time: '+str(end-start))
	peer1.sendline('mpassed-all')
	peer1.expect('Messages passed by all peers in network: (\d+)\r\n')
	mpassed = re.compile('\d+').search(str(peer1.after)).group()
	print('total messages: '+mpassed)

except pexpect.TIMEOUT as err:
	print('peer1.before: '+str(peer1.before))
	print('peer1.after: '+str(peer1.after))
	print('peer2.before: '+str(peer2.before))
	print('peer2.after: '+str(peer2.after))
	raise err