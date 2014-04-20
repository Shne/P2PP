~~Remove Recipient, just try to decode~~

~~Change searchID to use MD5 hash instead, do not send, generate on the fly~~

~~Error handling -> missing friends, missing secret, dead peer, uzw.~~

~~Tag certain calls to be non-accessible to RPC (key handling)  #I did the reverse~~ 

~~basic ack and signature/verification~~

improvement: use nonce when encrypting message, so same message can be sent more than once and better security #Doesn't the encrypter thing dothis?

improvement: What if multiple members return signature? Eg. malicious client. Might be an idea to get a list, and check everyone #see k-walker

Allow senders to sign message, take as parameter , check against friends

k-walker, send message to network, don't wait for return value, send ack back in same way

Improvement: Resend until ack is returned 
