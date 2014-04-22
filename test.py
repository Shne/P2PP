#!/usr/bin/python3
# you must install pexpect for this to work:
#	sudo apt-get install python3-pip
#	sudo pip3 install pexpect
import time
import pexpect

try:
	setup = pexpect.spawn('./setup.py', timeout=5)
	herp = pexpect.spawn('./interactive_peer.py localhost 8200 herp 5', timeout=5)
	derp = pexpect.spawn('./interactive_peer.py localhost 8201 derp 5', timeout=5)

	#setup herp
	herp.expect('>')
	herp.sendline('secret private.pem')
	herp.expect('>')
	herp.sendline('hello')
	herp.expect('>')

	#setup derp
	derp.expect('>')
	derp.sendline('secret private2.pem')
	derp.expect('>')
	derp.sendline('hello')
	derp.expect('>')

	# wait for network to manifest
	time.sleep(2)

	# befriend eachother
	herp.sendline('friend derp public2.pem')
	herp.expect('>')
	derp.sendline('friend herp public.pem')
	derp.expect('>')

	#send message via flooding
	msg = 'plplplplplp'
	herp.sendline('message derp '+msg)
	derp.expect('Received Message from herp: '+msg+'\r\n')
	herp.expect('derp received message! \(verified\)\r\n')
	print('Flooding message success!')

	# send message via k walker
	herp.sendline('kmessage derp '+msg)
	derp.expect('Received Message from herp: '+msg+'\r\n')
	herp.expect('Message delivered and acknowledged:.+\r\n')
	print('KWalker message success!')
except pexpect.TIMEOUT as err:
	print('herp.before: '+str(herp.before))
	print('herp.after: '+str(herp.after))
	print('derp.before: '+str(derp.before))
	print('derp.after: '+str(derp.after))
	raise err