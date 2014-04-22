~~Remove Recipient, just try to decode~~

~~Change searchID to use MD5 hash instead, do not send, generate on the fly~~

~~Error handling -> missing friends, missing secret, dead peer, uzw.~~

~~Tag certain calls to be non-accessible to RPC (key handling)  #I did the reverse~~ 

~~basic ack and signature/verification~~

~~k-walker, send message to network, don't wait for return value, send ack back in same way #Kris Dibz~~

~~improvement: use nonce when encrypting message, so same message can be sent more than once and better security #Doesn't the encrypter thing do this?~~

improvement: What if multiple members return signature? Eg. malicious client. Might be an idea to get a list, and check everyone #See k-walker #jhk: so is it done?

~~Allow senders to sign message (take as parameter, check against friends)~~

Improvement: Resend until ack is returned (Use higher and higher ttl/k/sleep time)

~~Improvement: If we send the same message from 2 sources to the same peer, the ack is valid for both, use a Nonce #messages are nonced now~~

Improvement: Work out something better for k/ttl for k-walker delivery #jhk: what is 'better'?

Error-proof k-walker/ack connection errors (See flooding version for guidance)

encrypt all xml-rpc traffic. use Diffie-Hellman to exchange secret
	#the xml-rpc traffic could possibly be wrapped like this: http://stackoverflow.com/questions/5690733/xmlrpc-server-over-https-in-python-3/18444798#18444798
	#some example Diffie-Hellman python code:
		http://code.google.com/p/zs-crypto/source/browse/zs/tools/diffie_hellman.py?r=8017268f3e472f4f2f671eb9595ee9574e07b5c7
		http://blog.markloiseau.com/2013/01/diffie-hellman-tutorial-in-python/