~~Remove Recipient, just try to decode~~
~~Change searchID to use MD5 hash instead, do not send, generate on the fly~~
~~Error handling -> missing friends, missing secret, dead peer, uzw.~~
~~Tag certain calls to be non-accessible to RPC (key handling)  #I did the reverse~~ 
Start on Milestone 2
~~basic ack and signature/verification~~
improvement: use nonce when encrypting message, so same message can be sent more than once and better security
improvement: What if multiple members return signature? Eg. malicious client. Might be an idea to get a list, and check everyone