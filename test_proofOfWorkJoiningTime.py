#!/usr/bin/python3
# you must install pexpect for this to work:
#	sudo apt-get install python3-pip
#	sudo pip3 install pexpect
import time
import pexpect
from peer import Peer
import random
import argparse


parser = argparse.ArgumentParser(description='Test Script')
parser.add_argument('-peers', type=int, help='Number of peers to set up', default=20)
args = parser.parse_args()

try:
    #print('Setting up network...')
    #setup = pexpect.spawn('python3.4 setup.py -peers 100', timeout=2000)
    #setup.expect('>')
    start = time.time()
    numberOfPeers = args.peers
    names = ['Peer'+str(x) for x in range(numberOfPeers)]
    IP = 'localhost'
    ports = [7300+x for x in range(numberOfPeers)]

    for (i,name) in enumerate(names):
        limit = 3
        while random.choice([True, True, True, False]):
            limit += 1
        peer = Peer(name, IP, ports[i], str(limit))
        peer.addResource(name, name + " iz best peer")
        peer.multicast()
        peer.startListeningForMulticast()
        peer.startFindingNeighbours()
        peer.startLookingForDeadNeighbours()
        peer.startSendingCoverTraffic()

    end = time.time()
    totalTime = '{:.2f}'.format(end-start)
    print(totalTime + ' sec to join network for ' + str(numberOfPeers) + ' peers')

    with open("proofOfWOrkJoiningTimeTestData.txt", "a") as testfile:
        testfile.write(str(numberOfPeers) + ", " + str(totalTime) + "\n")
        testfile.close()



except pexpect.TIMEOUT as err:
    print('Timeout error')
    raise err
