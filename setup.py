#!/usr/bin/python3
from peer import Peer
import random



numberOfPeers = 35

names = ['P'+str(x) for x in range(numberOfPeers)]
IP = 'localhost'
ports = [8000+x for x in range(numberOfPeers)]


for (i,name) in enumerate(names):
	limit = 3
	while random.choice([True, True, True, False]):
		limit = limit + 1
	peer = Peer(name, IP, ports[i], str(limit))
	peer.addResource(name, name + " iz best peer")
	peer.multicast()
	peer.startListeningForMulticast()
	peer.startFindingNeighbours()
	peer.startLookingForDeadNeighbours()

input()