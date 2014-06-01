Files:
DH.pem
	needed for Diffie-Hellman
hashcash.py
	the HashCash library
__init__.py
	allows importing from directory in python
peer.py
	main implementation file
private.pem, private2.pem, public.pem, public2.pem
	public-private key pairs. included to make testing easier
README.txt
	this file
setup.py
	script to allow quick setup of many peers

EXAMPLE OF USE:
using 3 terminals:
TERM1:
	./setup.py
TERM2:
	./interactive_peer.py localhost 8501 herp 5
	hello
	secret private.pem
TERM3:
	./interactive_peer.py localhost 8502 derp 5
	hello
	secret private2.pem
	friend herp public.pem
TERM2:
	friend derp public2.pem
	kmessage derp messagetext

Expected output:
TERM2:
	Sending message:herp/1
	sending message
	Message delivered and acknowledged: herp/1
TERM3:
	Received Message from herp: messagetext
