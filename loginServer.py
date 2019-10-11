import sys
import socket
from model import *
import json
import uuid
import stomp
import boto3
import time

class DBControl(object):
	def __init__(self, svr_port, mq_ip, mq_port=61613):
		self.svr_port = svr_port
		self.mq_ip = mq_ip
		'''try:
			self.mq = stomp.Connection([(mq_ip, 61613)])
			self.mq.start()
			self.mq.connect(wait=True)
		except Exception as e:
			print(e, file=sys.stderr)'''
		self.appsvrTable = {}
		''' instanceId ->
			{
				'addr' : ip_port
				'instance' : ec2_instance
				'users' : [users]
			}]'''
		self.servermap = {} # user -> instanceId
		#---------use tokens to represent users---------#
		
		#get aws token from file
		self.aws_access_key_id=None
		self.aws_secret_access_key=None
		self.aws_session_token=None

		f=open('credentials','r')
		for line in f:
			if line.startswith('aws_access_key_id='):
				self.aws_access_key_id=line[len('aws_access_key_id='):].strip()
			if line.startswith('aws_secret_access_key='):
				self.aws_secret_access_key=line[len('aws_secret_access_key='):].strip()
			if line.startswith('aws_session_token='):
				self.aws_session_token=line[len('aws_session_token='):].strip()
		f.close()
		
		#ec2 resource
		self.resource=boto3.resource('ec2',region_name='us-east-1',\
			aws_access_key_id = self.aws_access_key_id,\
			aws_secret_access_key = self.aws_secret_access_key,\
			aws_session_token = self.aws_session_token)
		
		#get aws resouces
		client=boto3.client('ec2',region_name='us-east-1',\
			aws_access_key_id=self.aws_access_key_id,\
			aws_secret_access_key=self.aws_secret_access_key,\
			aws_session_token=self.aws_session_token)
		
		#get AMI ID whose name is server
		imgs=client.describe_images(Filters=[{'Name':'name','Values':['server']}])['Images']
		self.imgID=imgs[0]['ImageId']
		
		#get security groups ID whose name is server (and default)
		sgs=client.describe_security_groups(Filters=[{'Name':'group-name','Values':['server','default']}])['SecurityGroups']
		self.sgsID=[sg['GroupId'] for sg in sgs]
		
		#UserData for instance creation
		self.userData=\
		'''#!/bin/bash
		cd /home/ec2-user/hw/
		sudo mount -t efs fs-2ba9d5ca:/ db
		echo "efs mount completed"
		python3 server.py 0.0.0.0 {} {} &
		echo "server started"
		'''.format(self.svr_port, self.mq_ip)
		
		pass

	def addAppUser(self,token):#return addr
		#check if login already, i.e. already assigned an appsvr
		if token in self.servermap:
			return self.appsvrTable[self.servermap[token]]['addr']
		
		
		#check for appsvr capacity
		appsvrID=None
		maxUserNum=10
		if len(self.appsvrTable) == 0 or all([True if len(self.appsvrTable[svrID]['users']) == maxUserNum else False for svrID in self.appsvrTable]):
			#start new appsvr
			appsvrID = self.startNewAppServer()
			self.servermap[token] = appsvrID
			self.appsvrTable[appsvrID]['users'].append(token)
			
		else:#find an appsvr
			for svrID in self.appsvrTable:
				if len(self.appsvrTable[svrID]['users']) < maxUserNum:
					appsvrID = svrID
					self.servermap[token] = appsvrID
					self.appsvrTable[appsvrID]['users'].append(token)
					break
		
		return self.appsvrTable[appsvrID]['addr']
		
		pass

	def removeAppUser(self,token):
		
		serverID = self.servermap[token]
		self.appsvrTable[serverID]['users'].remove(token)
		
		if len(self.appsvrTable[serverID]['users']) == 0:
			#terminate server
			self.appsvrTable[serverID]['instance'].terminate()
			del self.appsvrTable[serverID]
		
		del self.servermap[token]
		
		pass

	def startNewAppServer(self):#return instanceID
		
		#create instance
		newserver=self.resource.create_instances(ImageId=self.imgID,\
			InstanceType='t2.micro',\
			MinCount=1, MaxCount=1,\
			SecurityGroupIds=self.sgsID,\
			UserData=self.userData,\
			TagSpecifications=[{'ResourceType':'instance','Tags':[{'Key':'name','Value':'server_created_{}'.format(len(self.appsvrTable))}]}]\
			)[0]
			
		newserver.wait_until_running()
		time.sleep(5)
		newserver.load()#refresh attrs
		id=newserver.instance_id
		ip=newserver.public_ip_address
		
		#modify table
		self.appsvrTable[id]={
			'addr' : [ip,self.svr_port],
			'instance' : newserver,
			'users' : []
		}
		return id
		
		pass

	def __auth(func):
		def validate_token(self, token=None, *args):
			if token:
				t = Token.get_or_none(Token.token == token)
				if t:
					return func(self, t, *args)
			return {
				'status': 1,
				'message': 'Not login yet'
			}
		return validate_token

	def register(self, username=None, password=None, *args):
		if not username or not password or args:
			return {
				'status': 1,
				'message': 'Usage: register <username> <password>'
			}
		if User.get_or_none(User.username == username):
			return {
				'status': 1,
				'message': '{} is already used'.format(username)
			}
		res = User.create(username=username, password=password)
		if res:
			return {
				'status': 0,
				'message': 'Success!'
			}
		else:
			return {
				'status': 1,
				'message': 'Register failed due to unknown reason'
			}

	@__auth
	def delete(self, token, *args):
		if args:
			return {
				'status': 1,
				'message': 'Usage: delete <user>'
			}
		self.removeAppUser(token.token)
		token.owner.delete_instance()
		return {
			'status': 0,
			'message': 'Success!'
		}

	def login(self, username=None, password=None, *args):
		if not username or not password or args:
			return {
				'status': 1,
				'message': 'Usage: login <id> <password>'
			}
		res = User.get_or_none((User.username == username) & (User.password == password))
		if res:
			t = Token.get_or_none(Token.owner == res)
			if not t:
				token = uuid.uuid4()
				t = Token.create(token=str(token), owner=res, channel=token.hex[:15].upper())
			g = GroupMember.select().where(GroupMember.member == res)
			channels = []
			channels.append({
				'type': 0,
				'channel': t.channel
			})
			for i in g:
				channels.append({
					'type': 1,
					'name': i.group.name,
					'channel': i.group.channel
				})
			return {
				'status': 0,
				'token': t.token,
				'channel': channels,
				'message': 'Success!',
				'appsvr_addr': self.addAppUser(t.token)
			}
		else:
			return {
				'status': 1,
				'message': 'No such user or password error'
			}

	@__auth
	def logout(self, token, *args):
		if args:
			return {
				'status': 1,
				'message': 'Usage: logout <user>'
			}
		self.removeAppUser(token.token)
		'''print('----------------------')
		print(self.appsvrTable)
		print('----------------------')'''
		token.delete_instance()
		return {
			'status': 0,
			'message': 'Bye!'
		}

class Server(object):
	def __init__(self, ip, port, mq_ip):
		try:
			socket.inet_aton(ip)
			if 0 < int(port) < 65535:
				self.ip = ip
				self.port = int(port)
			else:
				raise Exception('Port value should between 1~65535')
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.db = DBControl(self.port, mq_ip)
			self.definedCmd = ['invite','list-invite','accept-invite','list-friend','post','receive-post','send','create-group','list-group','list-joined','join-group','send-group']
		except Exception as e:
			print(e, file=sys.stderr)
			sys.exit(1)

	def run(self):
		self.sock.bind((self.ip, self.port))
		self.sock.listen(100)
		socket.setdefaulttimeout(0.1)
		while True:
			try:
				conn, addr = self.sock.accept()
				with conn:
					cmd = conn.recv(4096).decode()
					resp = self.__process_command(cmd)
					conn.send(resp.encode())
			except Exception as e:
				print(e, file=sys.stderr)

	def __process_command(self, cmd):
		command = cmd.split()
		if len(command) > 0:
			command_exec = getattr(self.db, command[0].replace('-', '_'), None)
			if command_exec:
				#print(command)
				return json.dumps(command_exec(*command[1:]))
		return self.__command_not_found(command[0])

	def __command_not_found(self, cmd):
		if cmd in self.definedCmd:
			return json.dumps({
				'status': 1,
				'message': 'Not login yet'
			})
		else:
			return json.dumps({
				'status': 1,
				'message': 'Unknown command {}'.format(cmd)
			})


def launch_server(ip, port, mq_ip):
	c = Server(ip, port, mq_ip)
	c.run()

if __name__ == '__main__':
	if sys.argv[1] and sys.argv[2] and sys.argv[3]:
		launch_server(sys.argv[1], sys.argv[2], sys.argv[3])
