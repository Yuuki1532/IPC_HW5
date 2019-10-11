import sys
import socket
from model import *
import json
import uuid
import stomp


class DBControl(object):
	def __init__(self, mq_ip, mq_port=61613):
		try:
			self.mq = stomp.Connection([(mq_ip, 61613)])
			self.mq.start()
			self.mq.connect(wait=True)
		except Exception as e:
			print(e, file=sys.stderr)

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

	@__auth
	def invite(self, token, username=None, *args):
		if not username or args:
			return {
				'status': 1,
				'message': 'Usage: invite <user> <id>'
			}
		if username == token.owner.username:
			return {
				'status': 1,
				'message': 'You cannot invite yourself'
			}
		friend = User.get_or_none(User.username == username)
		if friend:
			res1 = Friend.get_or_none((Friend.user == token.owner) & (Friend.friend == friend))
			res2 = Friend.get_or_none((Friend.friend == token.owner) & (Friend.user == friend))
			if res1 or res2:
				return {
					'status': 1,
					'message': '{} is already your friend'.format(username)
				}
			else:
				invite1 = Invitation.get_or_none((Invitation.inviter == token.owner) & (Invitation.invitee == friend))
				invite2 = Invitation.get_or_none((Invitation.inviter == friend) & (Invitation.invitee == token.owner))
				if invite1:
					return {
						'status': 1,
						'message': 'Already invited'
					}
				elif invite2:
					return {
						'status': 1,
						'message': '{} has invited you'.format(username)
					}
				else:
					Invitation.create(inviter=token.owner, invitee=friend)
					return {
						'status': 0,
						'message': 'Success!'
					}
		else:
			return {
				'status': 1,
				'message': '{} does not exist'.format(username)
			}
		pass

	@__auth
	def list_invite(self, token, *args):
		if args:
			return {
				'status': 1,
				'message': 'Usage: list-invite <user>'
			}
		res = Invitation.select().where(Invitation.invitee == token.owner)
		invite = []
		for r in res:
			invite.append(r.inviter.username)
		return {
			'status': 0,
			'invite': invite
		}

	@__auth
	def accept_invite(self, token, username=None, *args):
		if not username or args:
			return {
				'status': 1,
				'message': 'Usage: accept-invite <user> <id>'
			}
		inviter = User.get_or_none(User.username == username)
		invite = Invitation.get_or_none((Invitation.inviter == inviter) & (Invitation.invitee == token.owner))
		if invite:
			Friend.create(user=token.owner, friend=inviter)
			invite.delete_instance()
			return {
				'status': 0,
				'message': 'Success!'
			}
		else:
			return {
				'status': 1,
				'message': '{} did not invite you'.format(username)
			}
		pass

	@__auth
	def list_friend(self, token, *args):
		if args:
			return {
				'status': 1,
				'message': 'Usage: list-friend <user>'
			}
		friends = Friend.select().where((Friend.user == token.owner) | (Friend.friend == token.owner))
		res = []
		for f in friends:
			if f.user == token.owner:
				res.append(f.friend.username)
			else:
				res.append(f.user.username)
		return {
			'status': 0,
			'friend': res
		}

	@__auth
	def post(self, token, *args):
		if len(args) <= 0:
			return {
				'status': 1,
				'message': 'Usage: post <user> <message>'
			}
		Post.create(user=token.owner, message=' '.join(args))
		return {
			'status': 0,
			'message': 'Success!'
		}

	@__auth
	def receive_post(self, token, *args):
		if args:
			return {
				'status': 1,
				'message': 'Usage: receive-post <user>'
			}
		res = Post.select().where(Post.user != token.owner).join(Friend, on=((Post.user == Friend.user) | (Post.user == Friend.friend))).where((Friend.user == token.owner) | (Friend.friend == token.owner))
		post = []
		for r in res:
			post.append({
				'id': r.user.username,
				'message': r.message
			})
		return {
			'status': 0,
			'post': post
		}

	@__auth
	def send(self, token, username=None, *args):
		if not args or not username:
			return {
				'status': 1,
				'message': 'Usage: send <user> <friend> <message>'
			}
		else:
			user = User.get_or_none(User.username == username)
			if user:
				friend = Friend.get_or_none(((Friend.user == token.owner) & (Friend.friend == user))
								| ((Friend.friend == token.owner) & (Friend.user == user)))
				if friend:
					t = Token.get_or_none(Token.owner == user)
					if t:
						msg = {
							'type': 0,
							'from': token.owner.username,
							'to': user.username,
							'message': " ".join(args)
						}
						self.mq.send("/queue/" + t.channel, json.dumps(msg))
						return {
							'status': 0,
							'message': 'Success!'
						}
					else:
						return {
							'status': 1,
							'message': '{} is not online'.format(username)
						}
				else:
					return {
						'status': 1,
						'message': '{} is not your friend'.format(username)
					}
			else:
				return {
					'status': 1,
					'message': 'No such user exist'
				}

	@__auth
	def create_group(self, token, group_name=None, *args):
		if not group_name or args:
			return {
				'status': 1,
				'message': 'Usage: create-group <user> <group>'
			}
		group = Group.get_or_none(Group.name == group_name)
		if not group:
			channel = uuid.uuid4().hex[:20].upper()
			g = Group.create(name=group_name, member=token.owner, channel=channel)
			GroupMember.create(group=g, member=token.owner)
			return {
				'status': 0,
				'message': 'Success!',
				'channel': channel
			}
		else:
			return {
				'status': 1,
				'message': '{} already exist'.format(group_name)
			}

	@__auth
	def list_group(self, token, *args):
		if args:
			return {
				'status': 1,
				'message': 'Usage: list-group <user>'
			}
		groups = Group.select()
		res = []
		for g in groups:
			res.append(g.name)
		return {
			'status': 0,
			'group': res
		}

	@__auth
	def list_joined(self, token, *args):
		if args:
			return {
				'status': 1,
				'message': 'Usage: list-joined <user>'
			}
		groups = GroupMember.select().where(GroupMember.member == token.owner)
		res = []
		for g in groups:
			res.append(g.group.name)
		return {
			'status': 0,
			'group': res
		}

	@__auth
	def join_group(self, token, group_name=None, *args):
		if not group_name or args:
			return {
				'status': 1,
				'message': 'Usage: join-group <user> <group>'
			}
		group = Group.get_or_none(Group.name == group_name)
		if group:
			added = GroupMember.select().where((GroupMember.group == group) & (GroupMember.member == token.owner))
			if not added:
				GroupMember.create(group=group, member=token.owner)
				return {
					'status': 0,
					'message': 'Success!',
					'channel': group.channel
				}
			else:
				return {
					'status': 1,
					'message': 'Already a member of {}'.format(group_name)
				}
		else:
			return {
				'status': 1,
				'message': '{} does not exist'.format(group_name)
			}

	@__auth
	def send_group(self, token, group_name=None, *args):
		if not args or not group_name:
			return {
				'status': 1,
				'message': 'Usage: send-group <user> <group> <message>'
			}
		else:
			group = Group.get_or_none(Group.name == group_name)
			if group:
				g = GroupMember.get_or_none((GroupMember.group == group) & (GroupMember.member == token.owner))
				if g:
					msg = {
						'type': 1,
						'from': token.owner.username,
						'to': g.group.name,
						'message': " ".join(args)
					}
					self.mq.send('/topic/' + g.group.channel, json.dumps(msg))
					return {
						'status': 0,
						'message': 'Success!'
					}
				else:
					return {
						'status': 1,
						'message': 'You are not the member of {}'.format(group_name)
					}
			else:
				return {
					'status': 1,
					'message': 'No such group exist'
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
			self.db = DBControl(mq_ip)
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
