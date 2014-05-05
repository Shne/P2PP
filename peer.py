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

import traceback

from socketserver import ThreadingMixIn

from multiprocessing.pool import ThreadPool #keep it secret, keep it safe

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

import ssl

import http.client

import base64

	#########################
	# Classes for safer RPC #
	#########################

class RPCThreading(ThreadingMixIn, SimpleXMLRPCServer): #I have literally no idea what this does, except work
	def _dispatch(self, method, params):
		func = None
		try:
			func =  getattr(self.instance, method).RPC #Only allow methods tagged as RPC methods to be called from RPC
		except (KeyError, AttributeError) as err:
			print("Forbidden: " + method )
			return None
		try:
			return super(RPCThreading, self)._dispatch(method, params)
		except:
			traceback.print_exc()
			raise

class DHTransport(xmlrpc.client.Transport): #xmlrpc-client transport support ADH
	def __init__(self, use_datetime=False, use_builtin_types=False, artLatency=.0):
		self._use_datetime = use_datetime
		self._use_builtin_types = use_builtin_types
		self._connection = (None, None)
		self._extra_headers = []
		self.connections = []
		self.host = None
		self.artLatency = artLatency

	def getDHCardinality(self):
		return len(self.connections)

	def make_connection(self, host):
		time.sleep(self.artLatency) #artifical network delay
		context = ssl.SSLContext(ssl.PROTOCOL_SSLv23) 
		context.set_ciphers("ADH") #Anonymous Diffie Hellman, requires no certs
		context.load_dh_params("DH.pem") #Precomputed DH primes

		if not (self.host == host):
			connections = []
			self.host = host
		viables = [connection for connection in self.connections if connection._HTTPConnection__state == 'Idle']
		if len(viables) == 0:
			connection = http.client.HTTPSConnection(host, context = context)
			self.connections.append(connection)
			return connection
		else:
			return viables[0]

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

def hash(data):
	h = SHA256.new()
	h.update(data)
	return h.digest()

def nonceMsg(msg):
    nonce = random.random()
    noncedMsg = msg + str(nonce)
    return (noncedMsg, nonce)

def unnonceMsg(noncedMsg, nonce):
	return noncedMsg[:0-len(str(nonce))]

def getRandomString(N):
	return ('%0' + str(N) + 'x') % random.randrange(16**N)

#Fuctions tagged as @RPC will get the correct attribute
def RPC(func):
	func.RPC = True
	return func


class Peer:
	def __init__(self, name, IP, port, peerLimit, artLatency=.0):
		self.name = name
		self.IP = IP
		self.port = port
		self.address = IP+':'+str(port)
		self.peerLimit = peerLimit
		self.artLatency = artLatency
		self.myString = strMake(self.name, self.address, self.peerLimit)
		self.peerSet = set([self.myString]) # adding ourselves to peerSet. design choice. to avoid a lot of bookkeeping.
		self.peerSetLock = threading.RLock()

		self.addNeighbourCounter = 0

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
		self.messagesSet = set([])
		self.acksSet = set([])
		self.awaitingAcks = dict()

		self.connections = dict()

	##################################
	# Make connection and cache it   #
	##################################

	def makeProxy(self, IPPort):
		url = "https://"+IPPort

		if(url in self.connections):
			return self.connections[url]
		else:
			self.connections[url] = xmlrpc.client.ServerProxy(url, transport=DHTransport(artLatency=self.artLatency))
			return self.connections[url]

	#######################
	# Simple peer listing #
	#######################

	@RPC
	def listPeers(self):
		return self.peerSet

	@RPC
	def hello(self, name, address, limit):
		contactStr = strMake(name, address, limit)
		with self.peerSetLock:
			self.peerSet.update([contactStr])
			# print(contactStr+' said hello. ' + self.name + ': updated peerSet: '+str(self.peerSet))
		return list(self.peerSet) #Not totally threadsafe, but safe enough


	def sayHello(self,IPPort):
		try:
			# print('saying hello to '+IPPort)
			serverProxy = self.makeProxy(IPPort)
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

		context = ssl.SSLContext(ssl.PROTOCOL_SSLv23) #See DHTransport
		context.set_ciphers("ADH")
		context.load_dh_params("DH.pem")

		server.socket = context.wrap_socket(server.socket, server_side=True)
		server.register_introspection_functions()

		server.register_instance(self)
		rpcThread = threading.Thread(target=server.serve_forever)
		rpcThread.daemon = True
		rpcThread.start()



	##############
	# Neighbours #
	##############
	@RPC
	def getNeighbours(self, plist):
		remList = [peer for peer in self.peerSet if strName(peer) in plist] #WOW
		#neighbourDict = {strName(x) + "(" + strLimit(x) + ")"  : makeProxy(strAddress(x)).listNeighbours() for x in remList} #OH SNAP
		neighbourDict = dict()
		for (i,peer) in enumerate(remList):
			print("Fetching neighbour lists:" + str(i) + "/" + str(len(remList)))
			pname = strName(peer) + "(" + strLimit(peer) + ")"
			try:
				neighbourDict[pname] = self.makeProxy(strAddress(peer)).listNeighbours()
			except ConnectionError as err:
				neighbourDict[pname] = []
		return neighbourDict

	@RPC
	def listNeighbours(self):
		return [strName(peer) + "(" + strLimit(peer) + ")" for peer in self.neighbourSet]

	@RPC
	def getNeighbourDegree(self):
		return len(self.neighbourSet)

	@RPC
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
				if self.makeProxy(strAddress(neighbour)).requestAddNeighbour(self.name, self.address, self.peerLimit):
					return self.addNeighbour(neighbour)
			except ConnectionError as err:
				print (self.name+': ConnectionError when becoming neighbour with ' + neighbour + '. is dead.')
				self.evictPeers([neighbour])
				return False
		return False



	#Based on pseudo-code from Week2 slides about GIA.

	@RPC
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
					nDegree = self.makeProxy(strAddress(n)).getNeighbourDegree()
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
				YDegree = self.makeProxy(address).getNeighbourDegree()
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
					self.makeProxy(strAddress(Z)).removeNeighbour(self.myString)
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
				self.addNeighbourCounter += 1
			return True
		else:
			return False

	@RPC
	def removeNeighbour(self, neighbour):
		if neighbour in self.neighbourSet:
			with self.neighbourSetLock:
				self.neighbourSet.remove(neighbour)
				self.neighbourSemaphore.release()
		return True

	def startFindingNeighbours(self):
		if not self.neighbourThread.isAlive():
			self.neighbourThread.start()			
	
		
	@RPC
	def ping(self):
		return True

	def pollPeer(self,IPPort):
		try:
			server = self.makeProxy(IPPort)			
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

		
	@RPC
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
			res = self.makeProxy(strAddress(peer)).floodSearch(key, searchId, TTL-1)
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

		
	@RPC
	def getResource(self, key):
		return self.resources[key]

	def get(self, key):
		try:
			return self.makeProxy(strAddress(self.resourceMap[key])).getResource(key)
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

		
	@RPC
	def handleWalkers(self, key, k, searchId, TTL, originalSourcePeer, sourcePeer):
		#has the original source peer already found a result?
		if TTL % 4 == 0: # only check each 4th step
			try:
				self.messagesPassed += 1
				if self.makeProxy(strAddress(originalSourcePeer)).hasKeyBeenFound(key):
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
				self.makeProxy(strAddress(originalSourcePeer)).walkerResultFound(key, self.myString)
			except ConnectionError as err:
				print(self.name+": k-walker result delivery failed at " + originalSourcePeer + ". is dead.")
				self.evictPeers([originalSourcePeer])
				return # no reason to continue search
			
		# should the walker die here?
		if TTL == 0:
			return
		
		# calculate which neighbours are eligible to be sent this search (not having been sent the same search before from this this peer)
		neighboursHavingSeenThisSearch = self.walkerSearchSentToNeighbours.get(searchId, [originalSourcePeer])
		neighboursHavingSeenThisSearch.append(sourcePeer)
		eligibleNeighbours = [n for n in self.neighbourSet if n not in neighboursHavingSeenThisSearch]
		if len(eligibleNeighbours) == 0:
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
		peerProxy = self.makeProxy(strAddress(peer))
		walkerThread = threading.Thread(target=peerProxy.handleWalkers, args=(key, k, searchId, TTL, originalSourcePeer, sourcePeer))
		walkerThread.start()
		
	@RPC
	def walkerResultFound(self, key, peer):
		self.resourceMap[key] = peer
		# print('result found at peer: '+peer)
		
	@RPC
	def hasKeyBeenFound(self, key):
		return key in self.resourceMap


	##############
	# STATISTICS #
	##############

	@RPC
	def getMessagesPassed(self):
		return self.messagesPassed

	@RPC
	def getAllMessagesPassed(self):
		return sum([self.makeProxy(strAddress(p)).getMessagesPassed() for p in self.peerSet])

	@RPC
	def getMessagesPerPeer(self):
		return {strName(peer) +"(" +  strLimit(peer) + ")" : self.makeProxy(strAddress(peer)).getMessagesPassed() for peer in self.peerSet}

	@RPC
	def resetMessagesCounter(self):
		self.messagesPassed = 0

	@RPC
	def resetAllMessagesCounter(self):
		for p in self.peerSet:
			self.makeProxy(strAddress(p)).resetMessagesCounter()


	@RPC
	def getAddNeighbourCounter(self):
		return self.addNeighbourCounter

	@RPC
	def getAllAddNeighbourCounter(self):
		with self.peerSetLock:
			return sum([self.makeProxy(strAddress(p)).getAddNeighbourCounter() for p in self.peerSet])

	@RPC
	def resetAddNeighbourCounter(self):
		self.addNeighbourCounter = 0

	@RPC
	def resetAllAddNeighbourCounter(self):
		for p in self.peerSet:
			self.makeProxy(strAddress(p)).resetAddNeighbourCounter()


	@RPC
	def getAvgDHCardinality(self):
		l = [conn('transport').getDHCardinality() for conn in self.connections.values()]
		return float(sum(l)/len(l))

	@RPC
	def getAllAvgDHCardinality(self):
		l = [self.makeProxy(strAddress(p)).getAvgDHCardinality() for p in self.peerSet]
		return float(sum(l)/len(l))



	@RPC
	def resetResourceMap(self):
		self.resourceMap = dict()

	@RPC
	def resetAllResourceMaps(self):
		for p in self.peerSet:
			self.makeProxy(strAddress(p)).resetResourceMap()

	@RPC
	def fullReset(self):
		self.resetMessagesCounter()
		self.resetResourceMap()
		self.searches = set([])
		self.resetAddNeighbourCounter()

	@RPC
	def fullResetAll(self):
		for p in self.peerSet:
			self.makeProxy(strAddress(p)).fullReset()


	#########
	# TESTS #
	#########

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

	#Add a friend with a simple name, and assign him the given public key
	def addFriend(self, name, keyFile):
		try:
			key = open(keyFile, 'r+b').read()
			publickey = RSA.importKey(key)
			cipher = PKCS1_OAEP.new(publickey) #Note PKCS1_OAEP is better known as RSAES-OAEP, and is the 'safe' way to do encryption with RSA
			signer = PKCS1_v1_5.new(publickey)
			self.friends[name] = (cipher, signer)
		except FileNotFoundError:
			print("Error, public key not found")

	def fetchFriend(self, name, keyHash):
		self.expandingRingFind(keyHash)
		key = self.get(keyHash)
		if(key is None):
			print("Unable to find friend")
			return

		#Better make sure things fit
		digest = SHA256.new()
		digest.update(key.encode('utf-8'))
		newHash = base64.b64encode(digest.digest()).decode('utf-8')
		if keyHash != newHash:
			print("Hash mismatch, got: "+ newHash + " expected: " + keyHash)
			return

		publickey = RSA.importKey(key.encode('utf8'))
		cipher = PKCS1_OAEP.new(publickey) #Note PKCS1_OAEP is better known as RSAES-OAEP, and is the 'safe' way to do encryption with RSA
		signer = PKCS1_v1_5.new(publickey)
		self.friends[name] = (cipher, signer)

	def publishKey(self, keyFile):
		try:
			key = open(keyFile, 'r+b').read()
			#Store the key in our own network
			digest = SHA256.new()
			digest.update(key)
			keyHash = base64.b64encode(digest.digest()).decode('utf-8')
			
			self.addResource(keyHash, key.decode('utf-8'))
			
			print("key added as: " + keyHash)
		except FileNotFoundError:
			print("Error, public key not found")

	#Set up your own private key
	def setSecret(self, keyFile):
		try:
			key = open(keyFile, 'r+b').read()
			privateKey = RSA.importKey(key) #Oh shit, this read 'private.pem', I was scared there
			self.cipher = PKCS1_OAEP.new(privateKey)
			self.signer = PKCS1_v1_5.new(privateKey)
		except FileNotFoundError:
			print("Error, private key not found")

	#####################
	# Flooding Messages #
	#####################

	#Send a message to a friend, not that you need to set up his public key first, fully async.
	def sendMessage(self, recipient, message):
		try:
			(cipher, signer) = self.friends[recipient]
		except KeyError:
			print("Error, unknown friend")
			return None

		owndigest = SHA256.new()
		owndigest.update(message.encode('utf-8'))
		sig = None
		try:
			sig = self.signer.sign(owndigest)
		except AttributeError:
			print("Note: You are sending signature-free messages")

		encryptedMessage = cipher.encrypt(message.encode('utf-8'))
		wrappedEncryptedMessage = xmlrpc.client.Binary(encryptedMessage)
		signature = self.receiveMessage(wrappedEncryptedMessage, xmlrpc.client.Binary(sig))
		if signature is None:
			print("Message not received!")
			return
		if signer.verify(owndigest, signature.data):
			print(recipient+' received message! (verified)')

	#Recieve message, check if it's for us, try to decode it and pass it on
	@RPC
	def receiveMessage(self, message, sig): #Note: message is an XMLRPC binary data wrapper
		mhash = hash(message.data)
		if mhash in self.messagesSet:
			return None
		self.messagesSet.add(mhash)
		if self.cipher is not None: # No reason to try to snoop without a secret
			try: #Only recipient can decode data
				decryptedMessage = self.cipher.decrypt(message.data)
				print('Received Message from ' + self.checkSender(decryptedMessage, sig) + ': ' +  decryptedMessage.decode('utf-8')) #Get binary data from XMLRPC wrapper, decrypt it, and decode it from UTF-8 from

				digest = SHA256.new()
				digest.update(decryptedMessage)
				signature = self.signer.sign(digest)
				return signature
			except ValueError:
				pass #We end up here when trying to decrypt with a non-matching key

		neighbourResults = self.pool.map(self.forwardMessage, [(peer, message, sig) for peer in self.neighbourSet])
		for result in neighbourResults:
			if result is not None:
				return result
		return None
		# for peer in self.neighbourSet:
		# 	self.forwardMessage(peer, message)

	#Helper to forward a message
	def forwardMessage(self, args):
		(peer, message, sig) = args
		try:
			peerProxy = self.makeProxy(strAddress(peer))
			return peerProxy.receiveMessage(message, sig)
		except ConnectionError as err:
			self.evictPeers([peer])
			return None
		# forwardThread = threading.Thread(target=peerProxy.receiveMessage, args=(message,)) #The comma, I have no idea
		# forwardThread.start()

	#####################
	# K-Walker Messages #
	#####################

	def kSendMessage(self, recipient, message, k, ttl):
		messageID = self.newSearchId()
		try:
			(cipher, signer) = self.friends[recipient]
		except KeyError:
			print("Error, unknown friend")
			return None

		(noncedMessage, nonce) = nonceMsg(message)
		encryptedMessage = cipher.encrypt(noncedMessage.encode('utf-8'))
		wrappedEncryptedMessage = xmlrpc.client.Binary(encryptedMessage)

		owndigest = SHA256.new()
		owndigest.update(noncedMessage.encode('utf-8'))
		signature = None
		try:
			signature = self.signer.sign(owndigest)
		except AttributeError:
			print("Note: You are sending signature-free messages")
		self.awaitingAcks[messageID] = (owndigest, signer)
		print("Sending message:" + messageID)
		for i in range(k):
			self.kReceiveMessage(wrappedEncryptedMessage, nonce, ttl, xmlrpc.client.Binary(signature))

	@RPC
	def kReceiveMessage(self, message, nonce, ttl, sig): #Note: message is an XMLRPC binary data wrapper
		if ttl < 0:
			return None
		if self.cipher is not None: # No reason to try to snoop without a secret
			try: #Only recipient can decode data
				decryptedMessage = self.cipher.decrypt(message.data)
				mhash = hash(message.data)
				if not (mhash in self.messagesSet): #We might end up here a lot
					self.messagesSet.add(mhash)
					unnoncedMessage = unnonceMsg(decryptedMessage, nonce)
					print('Received Message from ' + self.checkSender(decryptedMessage, sig) + ': ' +  unnoncedMessage.decode('utf-8')) #Get binary data from XMLRPC wrapper, decrypt it, and decode it from UTF-8 from
				digest = SHA256.new()
				digest.update(decryptedMessage)
				signature = self.signer.sign(digest)
				self.kAck(xmlrpc.client.Binary(signature), 32) #TODO:do something smarter about k/ttl
			except ValueError:
				pass #We end up here when trying to decrypt with a non-matching key
		forwardThread = threading.Thread(target=self.safeForwardKWalker, args=(message, nonce, ttl-1, sig))
		forwardThread.start()

	def safeForwardKWalker(self, message, nonce, ttl, sig):
		try:
			peer = random.sample(self.neighbourSet, 1)[0]
			self.makeProxy(strAddress(peer)).kReceiveMessage(message, nonce, ttl, sig)
		except:
			self.evictPeers([peer])

	@RPC
	def kAck(self, ack, ttl):
		if ttl < 0: #It's dead mang!
			return None
		if not (ack.data in self.acksSet): #Make sure we haven't checked the ack before
			for k, v in self.awaitingAcks.items(): #Check for each ack we're missing
				(digest, signer) = v
				if signer.verify(digest, ack.data):
					print("Message delivered and acknowledged: " + k)
					del self.awaitingAcks[k] #No need to keep this around
					break
		self.acksSet.add(ack.data) #remember we've checked this ack

		forwardThread = threading.Thread(target=self.safeForwardKAck, args=(ack, ttl-1))
		forwardThread.start() #To infinity, and beyond!

	def safeForwardKAck(self, ack, ttl):
		try:
			peer = random.sample(self.neighbourSet, 1)[0]
			self.makeProxy(strAddress(peer)).kAck(ack, ttl)
		except:
			self.evictPeers([peer])


	def checkSender(self, decryptedMessage, signature):
		digest = SHA256.new()
		digest.update(decryptedMessage)
		sender = "???"
		if signature is None:
			return sender
		for k, v in self.friends.items():
			(cipher, signer) = v
			if signer.verify(digest, signature.data):
				sender = k
			else:
				pass
		return sender

	##################
	# Cover Traffic  #
	##################

	@RPC
	def coverTraffic(self, mes):
		return getRandomString(random.randrange(1, 50))

	def startSendingCoverTraffic(self):
		threading.Thread(target = self.sendCoverTraffic).start()

	def sendCoverTraffic(self):
		while True:
			if len(self.neighbourSet) != 0:
				peer = random.sample(self.neighbourSet, 1)[0]
				try:
					self.makeProxy(strAddress(peer)).coverTraffic(getRandomString(random.randrange(1, 50)))
				except ConnectionError as err:
					self.evictPeers([peer])
			time.sleep(random.randrange(0, 50))

