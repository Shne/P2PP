#!/usr/bin/python3
import argparse
import os
import pprint
import re
from peer import Peer

def getColour(heatmap, value):
	r = value / max([1, max(heatmap.values())])
	g = 1-r
	return " [style=filled, color =\"#" + format(int(r*255)<<16 | int(g*255)<<8,"06x")+ "\"]"

def formatMap(map, heatmap = None):
	peerSet = set([peer for l in map.values() for peer in l])
	peerSet.update([peer for peer in map.keys()])
	edgeSet = set([])
	for k, v in map.items():
		for p in v:
			if(p < k):
				edgeSet.add("\"" + p + "\" -- \"" + k + "\";")
			else:
				edgeSet.add("\"" + k + "\" -- \"" + p + "\";")
	#pprint.pprint(peerSet)
	#pprint.pprint(edgeSet)

	str = "graph network {" + os.linesep
	for node in peerSet:
		if heatmap == None:
			str += "\"" + node + "\";" + os.linesep
		else:
			str += "\"" + node + "\"" + getColour(heatmap, heatmap[node]) + ";" + os.linesep
	for edge in edgeSet:
		str += edge + os.linesep
	str += "}"
	return str


parser = argparse.ArgumentParser(description='Simple XML-RPC Peer')
parser.add_argument('IP', type=str, help='IP Address to listen on')
parser.add_argument('port', type=int, help='Port to listen on')
parser.add_argument('name', type=str, help='My name')
parser.add_argument('limit', type=str, help='My peer limit')

args = parser.parse_args()

thisPeer = Peer(args.name, args.IP, args.port, args.limit)
thisPeer.addResource(args.name, args.name + ' is interactive peer')

while True:
	do = input()

	# PEERS
	match = re.match("plist", do)
	if match:
		pprint.pprint(thisPeer.listPeers())
		continue

	match = re.match("hello", do)
	if match:
		thisPeer.multicast()
		thisPeer.startListeningForMulticast()
		thisPeer.startFindingNeighbours()
		thisPeer.startLookingForDeadNeighbours()
		continue

	match = re.match(r"hello\s((\d+\.\d+\.\d+\.\d+\:\d+)|localhost\:\d+)", do)
	if match:
		thisPeer.sayHello(match.group(1))
		thisPeer.multicast()
		thisPeer.startListeningForMulticast()
		thispeer.startFindingNeighbours()
		thisPeer.startLookingForDeadNeighbours()
		continue


	# NEIGHBOURS
	match = re.match(r"nlist( -o (.*))?$", do)
	if match:
		if match.group(2):
			f = open(match.group(2), 'w')
			f.write(formatMap(thisPeer.getNeighbours([args.name])))
			f.close()
		else:
			print(formatMap(thisPeer.getNeighbours([args.name])))
		continue

	match = re.match(r"nlist-all( -o (.*))?$", do)
	if match:
		if match.group(2):
			f = open(match.group(2), 'w')
			f.write(formatMap(thisPeer.getAllNeighbours()))
			f.close()
		else:
			print(formatMap(thisPeer.getAllNeighbours()))
		continue

	match = re.match(r"nlist(\s[a-zA-Z0-9]+)+( -o (.*))?", do)
	if match:
		if match.group(3):
			f = open(match.group(3), 'w')
			f.write(formatMap(thisPeer.getAllNeighbours()))
			f.close()
		else:
			print(formatMap(thisPeer.getNeighbours(match.group(1).split(" "))))
		continue


	# FLOOD SEARCH
	match = re.match(r"find (\S+)\s*(\S*)", do)
	if match:
		if len(match.group(2)) > 0:
			TTL = int(match.group(2))
		else:
			TTL = 5
		print('Find result: '+str(thisPeer.simpleFloodFind(match.group(1), TTL)))
		continue

	match = re.match(r"ringfind (.+)", do)
	if match:
		print('Find result: '+str(thisPeer.expandingRingFind(match.group(1))))
		continue

	match = re.match(r"get (.+)", do)
	if match:
		print('Get result: '+str(thisPeer.get(match.group(1))))
		continue


	# K WALKER SEARCH
	match = re.match(r"kfind (\S+)\s*(\S*)\s*(\S*)$", do)
	if match:
		if len(match.group(2)) > 0:
			k = int(match.group(2))
		else:
			k = 8
		if len(match.group(3)) > 0:
			TTL = int(match.group(3))
		else:
			TTL = 24
		thisPeer.kwalkerSearch(match.group(1), k, TTL)
		continue


	# STATISTICS
	match = re.match(r"mpassed$", do)
	if match:
		print('Messages passed by '+thisPeer.name+': '+str(thisPeer.getMessagesPassed()))
		continue

	match = re.match(r"mpassed-all", do)
	if match:
		print('Messages passed by all peers in network: '+str(thisPeer.getAllMessagesPassed()))
		continue

	match = re.match(r"^mreset$", do)
	if match:
		thisPeer.resetMessagesCounter()
		continue

	match = re.match(r"^mreset-all$", do)
	if match:
		thisPeer.resetAllMessagesCounter()
		continue

	match = re.match(r"^fullreset$", do)
	if match:
		thisPeer.fullReset()
		continue

	match = re.match(r"^fullreset-all$", do)
	if match:
		thisPeer.fullResetAll()
		continue

	match = re.match(r"kfind-test\s*(\S*)\s*(\S*)", do)
	if match:
		if len(match.group(1)) > 0:
			k = int(match.group(1))
		else:
			k = 8
		if len(match.group(2)) > 0:
			TTL = int(match.group(2))
		else:
			TTL = 24
		thisPeer.testHitRate( k, TTL, len(thisPeer.listPeers()))
		continue

	match = re.match(r"^kfind-multitest$", do)
	if match:
		print('Random kWalker hitrate test for '+str(len(thisPeer.listPeers()))+' peers')
		ks = [pow(2,k) for k in range(6)]
		TTLs = [pow(2,TTL) for TTL in range(8)]
		for k in ks:
			for TTL in TTLs:
				print('k = '+str(k)+'  |  TTL = '+str(TTL))
				thisPeer.testHitRate(k, TTL, len(thisPeer.listPeers()))
		print('DONE!')
		continue

	match = re.match(r"bigtest", do)
	if match:
		thisPeer.bigTestOfTests()
		continue

	match = re.match(r"mpassed-ordered", do)
	if match:
		for k, v in thisPeer.getMessagesPerPeer().items():
			print(k + " , " + str(v))
		continue

	match = re.match(r"heatmap( -o (.*))?$", do)
	if match:
		if match.group(2):
			f = open(match.group(2), 'w')
			f.write(formatMap(thisPeer.getAllNeighbours(), thisPeer.getMessagesPerPeer()))
			f.close()
		else:
			print(formatMap(thisPeer.getAllNeighbours(), thisPeer.getMessagesPerPeer()))
		continue

	match = re.match(r"message ([a-zA-Z0-9]+) ([a-zA-Z0-9]+)$", do)
	if match:
		thisPeer.sendMessage(match.group(1), match.group(2))
		continue

	match = re.match(r"kmessage ([a-zA-Z0-9]+) ([a-zA-Z0-9]+)$", do)
	if match:
		thisPeer.kSendMessage(match.group(1), match.group(2), 1, 10)
		continue

	match = re.match(r"friend ([a-zA-Z0-9]+) (.+)$", do)
	if match:
		thisPeer.addFriend(match.group(1), match.group(2))
		continue

	match = re.match(r"secret (.+)$", do)
	if match:
		thisPeer.setSecret(match.group(1))
		continue

	# DEFAULT
	print('Command not recognized')