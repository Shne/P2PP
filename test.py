#!/usr/bin/python3
import time
import pexpect

setup = pexpect.spawn('./setup.py')
herp = pexpect.spawn('./interactive_peer.py localhost 8200 herp 5')
derp = pexpect.spawn('./interactive_peer.py localhost 8201 derp 5')

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

#send message
msg = 'plplplplplp'
herp.sendline('message derp '+msg)
derp.expect('Received Message from herp: '+msg+'\r\n')
herp.expect('derp received message! \(verified\)\r\n')

print('Success!')
