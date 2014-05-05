#!/usr/bin/python3
from peer import Peer
import random
import argparse

parser = argparse.ArgumentParser(description='Setup Script')
parser.add_argument('-peers', type=int, help='Number of peers to set up', default=30)
parser.add_argument('-late', type=float, help='Artificial Latency in RPC requests', default=.0)
args = parser.parse_args()
numberOfPeers = args.peers

names = ['P'+str(x) for x in range(numberOfPeers)]
IP = 'localhost'
ports = [8000+x for x in range(numberOfPeers)]


for (i,name) in enumerate(names):
	limit = 3
	while random.choice([True, True, True, False]):
		limit = limit + 1
	peer = Peer(name, IP, ports[i], str(limit), args.late)
	peer.addResource(name, name + " iz best peer")
	peer.multicast()
	peer.startListeningForMulticast()
	peer.startFindingNeighbours()
	peer.startLookingForDeadNeighbours()
	peer.startSendingCoverTraffic()

input('>')