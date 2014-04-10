from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
import xmlrpc.client

import threading
import socket
import struct
import sys
import threading

import inspect
import pprint

import random
import time
import math

from socketserver import ThreadingMixIn

from multiprocessing.pool import ThreadPool #keep it secret, keep it safe

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class RPCThreading(ThreadingMixIn, SimpleXMLRPCServer): #I have literally no idea what this does, except work
    pass

	###########
	# Helpers #
	###########
def strAddress(string):
	splitData = string.split('@')
	address = splitData[1].split('|')[0]
	return address

def strLimit(string):
	splitData = string.split('@')
	limit = splitData[1].split('|')[1]
	return limit

def strName(string):
	splitData = string.split('@')
	name = splitData[0]
	return name

def strMake(name, address, limit):
	return name+'@'+address+'|'+limit


def makeProxy(IPPort):
	url = "http://"+IPPort
	return xmlrpc.client.ServerProxy(url);



class Peer:
	def __init__(self, name, IP, port, peerLimit):
		self.name = name
		self.IP = IP
		self.port = port
		self.address = IP+':'+str(port)
		self.peerLimit = peerLimit
		self.myString = strMake(self.name, self.address, self.peerLimit)
		self.peerSet = set([self.myString]) # adding ourselves to peerSet. design choice. to avoid a lot of bookkeeping.
		self.peerSetLock = threading.RLock()

		self.neighbourSet = set([])
		self.neighbourSemaphore = threading.Semaphore(int(peerLimit))
		self.neighbourSetLock = threading.RLock()

		self.multicastThread = threading.Thread(target=self.listenForMulticast)
		self.multicastThread.daemon = True

		self.neighbourThread = threading.Thread(target=self.findNeighbours)
		self.neighbourThread.daemon = True

		self.neighbourEvictionThread = threading.Thread(target=self.checkForDeadNeighbours)
		self.neighbourEvictionThread.daemon = True

		self.searches = set([])
		self.searchCounter = 0
		self.messagesPassed = 0

		self.resourceLock = threading.RLock()
		self.resources = dict()
		self.resourceMap = dict()

		self.walkerSearchSentToNeighboursLock = threading.RLock()
		self.walkerSearchSentToNeighbours = dict() # keys are searchIds, values are neighbours

		self.startXMLRPCServer()
		# print(self.peerSet)

		self.pool = ThreadPool(processes = int(self.peerLimit))

		self.friends = dict()
		self.cipher = None

	#######################
	# Simple peer listing #
	#######################

	def listPeers(self):
		return self.peerSet

	def hello(self, name, address, limit):
		contactStr = strMake(name, address, limit)
		with self.peerSetLock:
			self.peerSet.update([contactStr])
			# print(contactStr+' said hello. ' + self.name + ': updated peerSet: '+str(self.peerSet))
		return list(self.peerSet) #Not totally threadsafe, but safe enough

	def sayHello(self,IPPort):
		try:
			# print('saying hello to '+IPPort)
			serverProxy = makeProxy(IPPort)
			contactList = serverProxy.hello(self.name, self.address, self.peerLimit)
			# print(IPPort+' gave contact list: ')
			# print(contactList)
			with self.peerSetLock:
				self.peerSet.update(set(contactList))
				# print('list of ' + self.name + ' is now: '+str(self.peerSet))
		except ConnectionError as err:
			print ('Error obtaining peer list from ' + IPPort + str(err))


	#################
	# Multiscasting #
	#################


	# the multicasting code was adapted from http://pymotw.com/2/socket/multicast.html
	def multicast(self):
		message = self.myString
		multicast_group = ('224.3.29.71', 10000)

		# Create the datagram socket
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		# Set the time-to-live for messages to 1 so they do not go past the local network segment.
		ttl = struct.pack('b', 1)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
		try:
			# Send data to the multicast group
			print('multicasting "%s"' % message)
			sent = sock.sendto(bytes(message, 'UTF-8'), multicast_group)
		finally:
			sock.close()


	# the multicasting code was adapted from http://pymotw.com/2/socket/multicast.html
	def listenForMulticast(self):
		multicast_group = '224.3.29.71'
		server_address = ('', 10000)

		# Create the socket
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		# Bind to the server address
		sock.bind(server_address)

		# Tell the operating system to add the socket to the multicast group on all interfaces.
		group = socket.inet_aton(multicast_group)
		mreq = struct.pack('4sL', group, socket.INADDR_ANY)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

		# Receive/respond loop
		while True:
			data, address = sock.recvfrom(1024)

			# print('received %s bytes from %s' % (len(data), address))
			decodedData = data.decode('utf-8')
			# print(decodedData)


			if strName(decodedData) != self.name:
				self.sayHello(strAddress(decodedData))
			else:
				print("That was me(" + self.name + "): don't say hello")

	def startListeningForMulticast(self):
		if not self.multicastThread.isAlive():
			self.multicastThread.start()


	#######################
	# XML RPC Serverstuff #
	#######################

	def startXMLRPCServer(self):
		server = RPCThreading((self.IP, self.port), logRequests=False, allow_none=True)
		server.register_introspection_functions()

		server.register_instance(self)
		rpcThread = threading.Thread(target=server.serve_forever)
		rpcThread.daemon = True
		rpcThread.start()



	##############
	# Neighbours #
	##############
	def getNeighbours(self, plist):
		remList = [peer for peer in self.peerSet if strName(peer) in plist] #WOW
		#neighbourDict = {strName(x) + "(" + strLimit(x) + ")"  : makeProxy(strAddress(x)).listNeighbours() for x in remList} #OH SNAP
		neighbourDict = dict()
		for (i,peer) in enumerate(remList):
			print("Fetching neighbour lists:" + str(i) + "/" + str(len(remList)))
			pname = strName(peer) + "(" + strLimit(peer) + ")"
			try:
				neighbourDict[pname] = makeProxy(strAddress(peer)).listNeighbours()
			except ConnectionError as err:
				neighbourDict[pname] = []
		return neighbourDict

	def listNeighbours(self):
		return [strName(peer) + "(" + strLimit(peer) + ")" for peer in self.neighbourSet]

	def getNeighbourDegree(self):
		return len(self.neighbourSet)

	def getAllNeighbours(self):
		return self.getNeighbours([strName(peer) for peer in self.peerSet])

	def findNeighbours(self):
		while True:
			self.neighbourSemaphore.acquire()
			if not self.neighbouriseMe():
				self.neighbourSemaphore.release()
			time.sleep(1)

	# Look for peers in peerSet that is not aready a neighbour and is not the peer itself.
	# if some potential peers are found
	# choose a random one of these.
	# Add me as choosen peer's neighbour if I'm not already it's neighbourSet and it has room for me.
	# If found peer is not already in my neighbourSet
	# add it as my neighbour if it also added me as neighbour.
	def neighbouriseMe(self):
		potentials = [peer for peer in self.peerSet if (not peer in self.neighbourSet) and (not strName(peer) == self.name)]
		if(len(potentials) != 0):
			neighbour = random.choice(potentials)
			try:
				if makeProxy(strAddress(neighbour)).requestAddNeighbour(self.name, self.address, self.peerLimit):
					if neighbour not in self.neighbourSet:
						with self.neighbourSetLock:
							self.neighbourSet.update([neighbour])
						return True
			except ConnectionError as err:
				print (self.name+': ConnectionError when becoming neighbour with ' + neighbour + '. is dead.')
				self.evictPeers([neighbour])
				return False
		return False



	#Based on pseudo-code from Week2 slides about GIA.
	def requestAddNeighbour(self, name, address, limit):
		Y = strMake(name, address, limit)
		if(self.neighbourSemaphore.acquire(False)):
			# we have room for another neighbour
			if not self.addNeighbour(Y):
				# we already had this neighbour
				self.neighbourSemaphore.release()
			return True

		else:
			# find subset of lower-capacity peers
			subset = [n for n in self.neighbourSet if strLimit(n) <= limit]
			if len(subset) == 0:
				# no such set -> reject
				return False

			# else find highest degree neighbour from subset
			Z = None
			ZDegree = 0
			for n in subset:
				try:
					nDegree = makeProxy(strAddress(n)).getNeighbourDegree()
					if nDegree > ZDegree:
						Z = n
						ZDegree = nDegree
				except ConnectionError as err:
					print(self.name+': Error getting neighbourhood degree from peer ' + n + str(err))
					self.evictPeers([n])
					# now we have room
					if(self.neighbourSemaphore.acquire(False)):
						if not self.addNeighbour(Y):
							# we already had this neighbour
							self.neighbourSemaphore.release()
						return True

			if Z is None:
				# no such neighbour -> reject
				return False

			neighbourMaxCapacity = max([strLimit(n) for n in self.neighbourSet])
			try:
				YDegree = makeProxy(address).getNeighbourDegree()
			except ConnectionError as err:
				print(self.name+': Error getting neighbourhood degree from peer ' + Y + str(err))
				return False
			if strLimit(Y) > neighbourMaxCapacity or ZDegree > YDegree:
				with self.neighbourSetLock:
					try:
						self.neighbourSet.remove(Z)
					except KeyError as err:
						return False #Someone stole our neighbour!!! Damn them!
				self.addNeighbour(Y)
				try:
					makeProxy(strAddress(Z)).removeNeighbour(self.myString)
				except ConnectionError as err:
					print (self.name+': Error removing myself as neighbour from peer ' + Z + str(err))
					self.evictPeers([Z])
				return True
			else:
				return False


	def addNeighbour(self, neighbour):
		if neighbour not in self.neighbourSet:
			with self.neighbourSetLock:
				self.neighbourSet.update([neighbour])
			return True
		else:
			return False

	def removeNeighbour(self, neighbour):
		if neighbour in self.neighbourSet:
			with self.neighbourSetLock:
				self.neighbourSet.remove(neighbour)
				self.neighbourSemaphore.release()
		return True

	def startFindingNeighbours(self):
		if not self.neighbourThread.isAlive():
			self.neighbourThread.start()			
	
	def ping(self):
		return True

	def pollPeer(self,IPPort):
		try:
			server = makeProxy(IPPort)			
			return server.ping()
		except ConnectionError as err:
			print(self.name+": Neighbourhood polling shows " + IPPort + " is dead")
			return False

	def checkForDeadNeighbours(self):
		while True:
			deadPeers = set([])
			for peer in set(self.neighbourSet):
				#is peer dead?
				if not self.pollPeer(strAddress(peer)):
					#Add peer to list of dead peers
					deadPeers.add(peer)
			self.evictPeers(deadPeers)
			time.sleep(10)

	def startLookingForDeadNeighbours(self):
		if not self.neighbourEvictionThread.isAlive():
			self.neighbourEvictionThread.start()

	def evictPeers(self, deadPeers):
		with self.neighbourSetLock:
			#Remove dead peers from neighbourset
			for deadNeighbour in deadPeers:
				if deadNeighbour in self.neighbourSet:
					self.neighbourSet.remove(deadNeighbour)
					self.neighbourSemaphore.release()
		with self.peerSetLock:
			#also remove dead peers from peerset
			self.peerSet.difference_update(deadPeers) 
		

	################
	# Flood Search #
	################

	def floodSearch(self, key, searchId, TTL):
		#print(self.name + " received search for " + key + " with id " + searchId + " --- Previously seen searchIds: " + str(self.searches))
		if key in self.resources.keys():
			self.resourceMap[key] = self.myString
			return self.myString
		if searchId in self.searches or TTL == 0:
			return None
		else:
			self.searches.update([searchId])
		self.pool.map(self.fwrap, [(peer, key, searchId, TTL) for peer in self.neighbourSet])
		try:
			return self.resourceMap[key]
		except KeyError as err:
			return None

	def fwrap(self,a):
		self.floodHelper(*a)

	def floodHelper(self, peer, key, searchId, TTL):
		try:
			self.messagesPassed += 1
			res = makeProxy(strAddress(peer)).floodSearch(key, searchId, TTL-1)
			if res is not None:
				self.resourceMap[key] = res
		except ConnectionError as err:
			print(self.name+": search failed to: " + peer + " for " + key)
			self.evictPeers([peer])

	def simpleFloodFind(self, key, TTL):
		result = self.floodSearch(key, self.newSearchId(), TTL)
		return result

	def expandingRingFind(self, key):
		result = None
		TTL = 0
		while result is None and TTL < len(self.peerSet):
			self.searchCounter = self.searchCounter + 1 #Necessary?
			result = self.floodSearch(key, self.newSearchId(), TTL)
			TTL += 1
		return result

	def newSearchId(self):
		self.searchCounter = self.searchCounter + 1
		return self.name + "/" + str(self.searchCounter)

	def addResource(self, key, value):
		self.resources[key] = value

	def getResource(self, key):
		return self.resources[key]

	def get(self, key):
		try:
			return makeProxy(strAddress(self.resourceMap[key])).getResource(key)
		except ConnectionError as err:
			print(self.name+": get failed for " + key + " at " + self.resourceMap[key] + ". is dead.")
			self.evictPeers(self.resourceMap[key])
		except KeyError as err:
			print(key+" hasn't been found yet!")

	#############
	# K-WALKERS #
	#############

	def kwalkerSearch(self, key, k, TTL):
		searchId = self.newSearchId()
		self.handleWalkers(key, k, searchId, TTL, self.myString, self.myString)


	def handleWalkers(self, key, k, searchId, TTL, originalSourcePeer, sourcePeer):
		#has the original source peer already found a result?
		if TTL % 4 is 0: # only check each 4th step
			try:
				self.messagesPassed += 1
				if makeProxy(strAddress(originalSourcePeer)).hasKeyBeenFound(key):
					return
			except ConnectionError as err:
				print(self.name+": k-walker check for search relevancy failed at " + originalSourcePeer + ". is dead.")
				self.evictPeers([originalSourcePeer])
				return # no reason to continue search

		# do I have this resource?
		self.searches.update([searchId])
		if key in self.resources.keys():
			try:
				self.messagesPassed += 1
				makeProxy(strAddress(originalSourcePeer)).walkerResultFound(key, self.myString)
			except ConnectionError as err:
				print(self.name+": k-walker result delivery failed at " + originalSourcePeer + ". is dead.")
				self.evictPeers([originalSourcePeer])
				return # no reason to continue search
			
		# should the walker die here?
		if TTL is 0:
			return
		
		# calculate which neighbours are eligible to be sent this search (not having been sent the same search before from this this peer)
		neighboursHavingSeenThisSearch = self.walkerSearchSentToNeighbours.get(searchId, [originalSourcePeer])
		neighboursHavingSeenThisSearch.append(sourcePeer)
		eligibleNeighbours = [n for n in self.neighbourSet if n not in neighboursHavingSeenThisSearch]
		if len(eligibleNeighbours) is 0:
			return

		neighboursSentThisSearch = []

		# if k is higher than amount of eligible neighbours, send some to each
		noOfWalkersForEachNeighbour = math.floor(k/len(eligibleNeighbours))
		if noOfWalkersForEachNeighbour > 0:
			for peer in eligibleNeighbours:
				try:
					self.forwardWalker(peer, key, noOfWalkersForEachNeighbour, searchId, TTL-1, originalSourcePeer, self.myString)
					neighboursSentThisSearch.append(peer)
				except ConnectionError as err:
					print(self.name+": k-walker start failed at " + peer + ". is dead.")
					self.evictPeers([peer])	

		# random sample which remaining neighbours to forward to
		kNeighbours = random.sample(eligibleNeighbours, k%len(eligibleNeighbours))
		for peer in kNeighbours:
			try:
				self.forwardWalker(peer, key, 1, searchId, TTL-1, originalSourcePeer, self.myString)
				neighboursSentThisSearch.append(peer)
			except ConnectionError as err:
				print(self.name+": k-walker start failed at " + peer + ". is dead.")
				self.evictPeers([peer])

		# update list of neighbours having seen this search
		with self.walkerSearchSentToNeighboursLock:
			neighboursSentThisSearch.extend(self.walkerSearchSentToNeighbours.get(searchId, [originalSourcePeer]))
			neighboursSentThisSearch.append(sourcePeer)
			self.walkerSearchSentToNeighbours[searchId] = neighboursSentThisSearch
		
	def forwardWalker(self, peer, key, k, searchId, TTL, originalSourcePeer, sourcePeer):
		self.messagesPassed += 1
		peerProxy = makeProxy(strAddress(peer))
		walkerThread = threading.Thread(target=peerProxy.handleWalkers, args=(key, k, searchId, TTL, originalSourcePeer, sourcePeer))
		walkerThread.start()
		
	def walkerResultFound(self, key, peer):
		self.resourceMap[key] = peer
		# print('result found at peer: '+peer)
			
	def hasKeyBeenFound(self, key):
		return key in self.resourceMap


	##############
	# STATISTICS #
	##############

	def getMessagesPassed(self):
		return self.messagesPassed

	def getAllMessagesPassed(self):
		return sum([makeProxy(strAddress(p)).getMessagesPassed() for p in self.peerSet])

	def getMessagesPerPeer(self):
		return {strName(peer) +"(" +  strLimit(peer) + ")" : makeProxy(strAddress(peer)).getMessagesPassed() for peer in self.peerSet}

	def resetMessagesCounter(self):
		self.messagesPassed = 0

	def resetAllMessagesCounter(self):
		for p in self.peerSet:
			makeProxy(strAddress(p)).resetMessagesCounter()

	def resetResourceMap(self):
		self.resourceMap = dict()

	def resetAllResourceMaps(self):
		for p in self.peerSet:
			makeProxy(strAddress(p)).resetResourceMap()

	def fullReset(self):
		self.resetMessagesCounter()
		self.resetResourceMap()
		self.searches = set([])

	def fullResetAll(self):
		for p in self.peerSet:
			makeProxy(strAddress(p)).fullReset()

	def testHitRate(self, k, TTL, samples):
		self.resetResourceMap()
		tests = 0
		#print("Starting hitrate test...")
		for p in random.sample(set(self.peerSet),samples): #long operation, better be threadsafe
			self.kwalkerSearch(strName(p), k, TTL)
			tests += 1
			#print("Working...")
			time.sleep(.2)
		#print("Waiting for stragglers...")
		time.sleep(4)
		print("Hit rate " + str(len(self.resourceMap)) + "/" + str(tests))

	def testFloodHitRate(self, TTL, samples):
		self.resetResourceMap()
		tests = 0
		#print("Starting hitrate test...")
		for p in random.sample(set(self.peerSet),samples): #long operation, better be threadsafe
			self.simpleFloodFind(strName(p), TTL)
			tests += 1
			#print("Working...")
			# time.sleep(3)
		print("Hit rate " + str(len(self.resourceMap)) + "/" + str(tests))

	def testRingFind(self,samples):
		self.resetResourceMap()
		tests = 0
		#print("Starting hitrate test...")
		for p in random.sample(set(self.peerSet),samples): #long operation, better be threadsafe
			self.expandingRingFind(strName(p))
			tests += 1
			#print("Working...")
			#time.sleep(1)
			# time.sleep(5)
		#print("Hit rate " + str(len(self.resourceMap)) + "/" + str(tests))

	def bigTestOfTests(self):
		print("Running huge test data")
		samples = 5
		for i in range(8):
			self.fullResetAll()
			print("Starting flooding test for TTL = " + str(i))
			self.testFloodHitRate(i, samples)
			print("Messages passed: " + str(self.getAllMessagesPassed()))
		self.fullResetAll()
		print("Starting ringfind test")
		self.testRingFind(samples)
		print("Messages passed: " + str(self.getAllMessagesPassed()))
		comboes = [4, 8, 16, 32, 64]
		for k in comboes:
			for ttl in comboes:
				self.fullResetAll()
				print("kwalker-test K: " + str(k) + " TTL: " + str(ttl) )
				self.testHitRate(k, ttl, samples)
				print("Messages passed: " + str(self.getAllMessagesPassed()))

	##############
	# Safety	 #
	##############

	def addFriend(self, name, key):
		publickey = RSA.importKey(open(key, 'r+b').read())
		cipher = PKCS1_OAEP.new(publickey)
		self.friends[name] = key

	def setSecret(self, key):
		private = RSA.importKey(open('private.pem', 'r+b').read())
		cipher = PKCS1_OAEP.new(private)
		self.cipher = cipher

	def sendMessage(self, recipient, message):
		searchId = self.newSearchId()
		self.receiveMessage(recipient, message.encode('utf-8'), searchId)

	def receiveMessage(self, recipient, message, searchId):
		if searchId in self.searches:
			return None
		self.searches.add(searchId)
		if recipient == self.name:
			print(message.data.decode('utf-8'))
		for peer in self.neighbourSet:
			self.forwardMessage(peer, recipient, message, searchId)

	def forwardMessage(self, peer, recipient, message, searchId):
		peerProxy = makeProxy(strAddress(peer))
		forwardThread = threading.Thread(target=peerProxy.receiveMessage, args=(recipient, message, searchId))
		forwardThread.start()