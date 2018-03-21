import argparse
import socket
import sys
import os
import threading
# from time import gmtime, strftime
import utils
import time
start_server = None


def start_server_closure(serverInstance):

    chat_server = serverInstance

    def start_server():
        print("Listening on port " + str(chat_server.port))
        print("Waiting for connections...\n")
        chat_server.start_listening()
        chat_server.server_shutdown()

    return start_server


class DB:

    def __init__(self, db_path):
        self.USERS_FILE = db_path + "/users.txt"
        self.BANNED_USERS_FILE = db_path + "/banusers.txt"
        self.CHANNELS_FILE = db_path + "/channels.txt"
        self.BANNER_FILE = db_path + "/banner.txt"

        # username -> {username: str, password: str, level: str, banned: bool}
        self.users = {}
        # str[]
        self.banned_users = []
        # name -> {name: str, description: str, password: str, channelops: str[]}
        self.channels = {}
        # str
        self.banner = None

        self.refresh_from_files()

    def refresh_from_files(self):
        """
        Loads the DB data with data from the appropriate files
        self.banner from the file at BANNER_FILE path
        self.users from the file at USERS_FILE path
        self.banned_users from the file at BANNED_USERS_FILE path
        self.channels from the file at CHANNELS_FILE path
        :return:
        """
        # Load banner message from file
        try:
            with open(self.BANNER_FILE) as banner_file:
                self.banner = banner_file.read()
        except IOError:
            pass

        # Load users from file
        for user_line in utils.get_file_lines(self.USERS_FILE):
            try:
                user_line_splitted = user_line.split(None, 3)

                username = user_line_splitted[0]

                user_password = user_line_splitted[1]
                if user_password == '@':
                    user_password = ''

                user_level = user_line_splitted[2]
                if user_level not in ["user", "channelop", "sysop", "admin"]:
                    user_level = "user"

                user_is_banned = user_line_splitted[3]
                if user_is_banned == "false":
                    user_is_banned = False
                elif user_is_banned == "true":
                    user_is_banned = True
                else:
                    user_is_banned = bool(user_is_banned)

                self.users[username] = {
                    'username': username,
                    'password': user_password,
                    'level': user_level,
                    'banned': user_is_banned
                }
            except IndexError:
                continue

        # Load banned users from file
        self.banned_users = utils.get_file_lines(self.BANNED_USERS_FILE)

        # Load channels from file
        for channel_line in utils.get_file_lines(self.CHANNELS_FILE):
            try:
                channel_line_splitted = channel_line.split(None, 3)

                channel_name = channel_line_splitted[0]

                channel_password = channel_line_splitted[2]
                if channel_password == '@':
                    channel_password = ''

                channel_ops = channel_line_splitted[3]
                self.channels[channel_name] = {
                    'name': channel_name,
                    'description': channel_line_splitted[1],
                    'password': channel_password,
                    'channelops': [channel_op.strip()
                                   for channel_op in channel_ops.split(",")
                                   for channel_op in channel_op.split(None)]
                }
            except IndexError:
                pass

    def persist_to_files(self):
        """
        Persists the DB data to the appropriate files
        self.banner to the file at BANNER_FILE path
        self.users to the file at USERS_FILE path
        self.banned_users to the file at BANNED_USERS_FILE path
        self.channels to the file at CHANNELS_FILE path
        :return:
        """
        # Persist banner
        try:
            with open(self.BANNER_FILE, "w") as banner_file:
                banner_file.write(self.banner)
        except IOError:
            pass

        # Persist users
        users_lines = []
        for user in self.users.values():
            user_password = user.get("password")
            if not user_password:
                user_password = "@"

            if user.get("banned"):
                banned = "true"
            else:
                banned = "false"
            users_lines.append(
                "%s %s %s %s" % (
                    user.get("username", ''),
                    user_password,
                    user.get("level"),
                    banned
                )
            )
        utils.save_file_lines(self.USERS_FILE, users_lines)

        # Persist banned users
        utils.save_file_lines(self.BANNED_USERS_FILE, self.banned_users)

        # Persist channels
        channels_lines = []
        for channel in self.channels.values():
            channel_password = channel.get("password")
            if not channel_password:
                channel_password = "@"

            channel_ops = ",".join(channel.get("channelops", []))
            channels_lines.append(
                "%s %s %s %s" % (
                    user.get("name"),
                    user.get("description"),
                    channel_password,
                    channel_ops
                )
            )


class Server:

    SERVER_CONFIG = {"BACKLOG": 15}

    HELP_MESSAGE = """
    > The list of commands available are:
    /quit - Exits the program.
    /list - Lists all the users in the chat room.
    please refer to https://tools.ietf.org/html/rfc2812 for the parameters of each command
    The commands supported by this chat are:
    AWAY CONNECT DIE
HELP INFO INVITE ISON
JOIN
KICK
KILL KNOCK LIST MODE NICK NOTICE PART OPER PASS
PING PONG PRIVMSG QUIT RESTART RULES SETNAME SILENCE TIME TOPIC USER USERHOST USERIP USERS VERSION W ALLOPS
 
WHO WHOIS
    \n\n""".encode('utf8')

    def __init__(self,
                 db,
                 host=socket.gethostbyname('localhost'),
                 port=50000,
                 allow_reuse_address=True):
        self.host = host
        self.port = port
        self.address = (self.host, self.port)
        self.clients = {}
        self.client_thread_list = []

        # key: name, value : address
        self.client_ips = {}
        # key: name, value : username
        self.client_usernames = {}
        # clients who are away
        self.clients_away = {}

        # key: nickname, value: name
        self.clients_nicknames = {}
        # key : name, value : password
        self.clients_passwords = {}

        # users, banned users, channels and banner db
        self.db = db
        # key: channel_name, value: name[]
        self.channel_users = {}
        # key : mode, value: name[]
        self.mode_of_users = {}
        # key : channel name  , value : topic
        self.channel_topic = {}

        self.online_users = []

        # clients who will be silenced
        # key: username of person blocking , value: name[] of people being blocked
        self.ignore_list = {}
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as error_message:
            sys.stderr.write("Failed to initialize the server. Error - %s\n", error_message.strerror)
            raise

        if allow_reuse_address:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind(self.address)
        except socket.error as error_message:
            sys.stderr.write('Failed to bind to (%s, %d). Error - %s\n', self.host, self.port, error_message.strerror)
            raise

    def listen_thread(self, default_greeting="\n> Welcome to our chat app!!! What is your name?\n"):
        while True:
            print("Waiting for a client to establish a connection\n")
            client_socket, client_address = self.server_socket.accept()
            print("Connection established with IP address {0} and port {1}\n".format(client_address[0],
                                                                                     client_address[1]))
            client_socket.send(default_greeting.encode('utf8'))
            client_thread = threading.Thread(target=self.client_thread, args=(client_socket, client_address))
            self.client_thread_list.append(client_thread)
            client_thread.start()

    def start_listening(self):
        self.server_socket.listen(Server.SERVER_CONFIG["BACKLOG"])
        listener_thread = threading.Thread(target=self.listen_thread)
        listener_thread.start()
        listener_thread.join()

    def server_shutdown(self):
        print("Shutting down chat server.\n")
        for client_thread in self.client_thread_list:
            client_thread.exit()
        self.server_socket.shutdown(socket.SHUT_RDWR)
        self.server_socket.close()

    def broadcast_message(self, message, name=''):
        for client_socket in self.clients:
            if self.clients[client_socket] + ': ' != name:
                client_socket.send((name + message).encode('utf8'))
            else:
                client_socket.send(('You: ' + message).encode('utf8'))

    def client_thread(self, client_socket, client_address, size=4096):
        name = client_socket.recv(size).decode('utf8')
        welcome_message = '> Welcome %s, type /help for a list of helpful commands.\n\n' % name
        client_socket.send(welcome_message.encode('utf-8'))
        chat_message = '\n> %s has joined the chat!\n' % name
        self.broadcast_message(chat_message)
        self.clients[client_socket] = name
        self.client_ips[name] = client_address
        self.clients_passwords[name] = ''

        while True:
            chat_message = client_socket.recv(size).decode('utf8').lower()

            if chat_message == '/quit':
                self.quit(client_socket, client_address, name)
                break
            elif chat_message == '/users':
                self.list_all_users(client_socket, name)
            elif chat_message == '/help':
                self.help(client_socket)
            elif chat_message.startswith('/away'):
                self.away(client_socket, chat_message.replace('/away', ''))
            elif chat_message.startswith('/connect'):
                user_parameters = chat_message.replace('/connect', '', 1).strip().split(' ')
                try:
                    target_server = user_parameters[0]
                except IndexError:
                    client_socket.send('> Required parameter target_server not provided\n'.encode('utf8'))
                    continue
                try:
                    target_port = user_parameters[1]
                except IndexError:
                    target_port = 80
                self.server_connect(client_socket, target_server, target_port)
            elif chat_message == '/die':
                self.server_die(client_socket)
            elif chat_message.startswith('/info'):
                remote_server = chat_message.replace('/info', '', 1).strip()
                self.server_information(client_socket, remote_server)
            elif chat_message.startswith('/ison'):
                nicknames = chat_message.replace('/ison', '', 1).strip().split(' ')
                self.ison(client_socket, nicknames)
            elif chat_message.startswith('/nick'):
                new_nickname = chat_message.replace('/nick', '', 1).strip()
                self.nick(client_socket, new_nickname)
            elif chat_message.startswith('/pass'):
                set_password = chat_message.replace('/pass', '', 1).strip()
                self.password(client_socket, set_password)
            elif chat_message == '/restart':
                self.restart_server()
            elif chat_message == '/rules':
                self.rules(client_socket)
            elif chat_message.startswith('/setname'):
                set_the_name = chat_message.replace('/setname', '', 1).strip()
                self.set_name(client_socket, set_the_name)
            elif chat_message.startswith('/invite'):
                parameters = chat_message.replace('/invite', '', 1).strip().split(" ")
                if len(parameters) != 2:
                    continue
                nickname = parameters[0]
                channel_name = parameters[1]
                self.invite(client_socket, nickname, channel_name)
            elif chat_message.startswith('/kick'):
                parameters = chat_message.replace('/kick', '', 1).strip().split(" ", 3)
                if len(parameters) != 2 or len(parameters) != 3:
                    continue
                channels = parameters[0].split(",")
                users = parameters[1].split(",")
                comment = None
                if len(parameters) == 3:
                    comment = parameters[2]
                if len(channels) == 1 and len(users) > 0:
                    for user in users:
                        self.kick(client_socket, channels[0], user, comment)
                elif len(channels) == len(users):
                    for (channel, user) in zip(channels, users):
                        self.kick(client_socket, channel, user, comment)
                else:
                    error_message=(""" in order to kick someone out, there MUST be
                    either one channel parameter and multiple user parameter, or as many
                    channel parameters as there are user parameters.\n""")
                    client_socket.send(error_message.encode('utf-8'))
            elif chat_message.startswith('/userip'):
                nickname = chat_message.replace('/userip', '', 1).strip()
                if nickname in self.clients_nicknames: # making sure this nickname exists
                    self.userip(client_socket, nickname)
                else: # nickname does not exist
                    client_socket.send("That nickname does not exist!\n".encode('utf8'))
                continue
            elif chat_message == '/version':
                self.version(client_socket)
            elif chat_message.startswith('/silence'):
                parameters = chat_message.replace('/silence', '', 1).strip().split()
                ignore_list = ",".join(self.ignore_list)
                if len(parameters) == 0:  # assuming you need a + or a - before the name being silenced
                    client_socket.send((ignore_list + "\n\n").encode('utf8'))
                else :
                    self.silence(client_socket, parameters)
            elif chat_message.startswith('/join'):
                parameters = chat_message.replace('/join', '', 1).strip().split()
                '''''
                leave_groups = False
                if len(parameters) == 3 and parameters[2] == "0":
                    leave_groups = True
                elif len(parameters) == 1 and parameters[0] == "0":
                    leave_groups = True

                if leave_groups:
                    for channel in self.channel_users:
                        if name in self.channel_users[channel]:
                            self.channel_users[channel].remove(name)
                
                if len(parameters) == 2 or len(parameters) == 3:
                    channels = parameters[0].split(",")
                    passwords = parameters[1].split(",")
                    for (channel, password) in zip(channels, passwords):
                        if password == "@":
                            password = None
                
                        self.join(client_socket, channel, password)
                        '''''
                if len(parameters) == 1 and parameters[0] != "0":
                    # channels = parameters[0].split(",")
                    channel = parameters[0]
                    self.join(client_socket, channel)
            elif chat_message.startswith('/oper'):
                parameters = chat_message.replace('/oper', '', 1).strip().split()
                if len(parameters) == 2:
                    username = parameters[0]
                    password = parameters[1]
                    self.oper(client_socket, username, password)
            elif chat_message.startswith('/mode'):
                parameters = chat_message.replace('/mode', '', 1).strip().split()
                if len(parameters) == 3:
                    nickname = parameters[0]
                    add_remove = parameters[1]
                    modes = parameters[2]
                    self.mode(client_socket, nickname, add_remove, modes)
            elif chat_message.startswith('/wallops'):
                wallops_message = chat_message.replace('/wallops', '', 1).strip()
                self.wallops(client_socket, wallops_message)
            elif chat_message.startswith('/topic'):
                parameters = chat_message.replace('/topic', '', 1).strip()
                new_parameters = parameters.split(" ", 1)
                channel = new_parameters[0]
                if len(new_parameters) == 2:
                    topic_message = new_parameters[1]
                    self.topic(client_socket, channel, topic_message)
                if len(new_parameters) == 1 :
                    self.topic(client_socket, channel, None)
            elif chat_message.startswith('/time'):
                parameter = chat_message.replace('/time', '', 1).strip()
                self.time(client_socket, parameter)
            elif chat_message.startswith('/userhost'):
                parameters = chat_message.replace('/userhost', '', 1).strip().split(" ")
                if len(parameters) < 6:
                    self.userhost(client_socket, parameters)
            elif chat_message.startswith('/kill'):
                parameters = chat_message.replace('/kill','',1).strip().split(" ", 1)
                nickname = parameters[0]
                message = parameters[1]
                self.kill(client_socket, nickname, message)
            elif chat_message.startswith('/list'):
                parameters = chat_message.replace('/list', '', 1).strip().split(" ")
                print(len(parameters))
                if len(parameters) == 1:
                    self.list(client_socket, None)
                elif len(parameters) > 1:
                    channels = parameters[0].split(',')
                    self.list(client_socket, channels)

            elif chat_message.startswith('/privmsg'):
                parameters = chat_message.replace('/privmsg', '', 1).strip().split(" ")
                if len(parameters) != 2:
                    continue
                else:
                    self.privmsg(client_socket, parameters[0], parameters[1])
            elif chat_message.startswith('/notice'):
                parameters = chat_message.replace('/notice', '', 1).strip().split(" ")
                if len(parameters) != 2:
                    continue
                self.notice(parameters[0], parameters[1])
            elif chat_message.startswith('/knock'):
                parameters = chat_message.replace('/knock', '', 1).strip().split(" ", 1)
                if len(parameters) == 2:
                    self.knock(client_socket, parameters[0], parameters[1])
                else:
                    automated_message = "{name} requesting an invite to join channel".format(
                        name=self.clients[client_socket]
                    )
                    self.knock(client_socket, parameters[0], automated_message)
            elif chat_message.startswith('/part'):
                h = chat_message.replace('/part', '', 1)
                print(h)
                parameters = h.strip().split(" ", 1)
                print(parameters)
                if len(parameters) == 1:
                    channels = parameters
                    message = None
                    self.part(client_socket, channels, message)
                elif len(parameters) ==2:
                    channels = parameters[0]
                    message = parameters[1]
                    # print(channels)
                    self.part(client_socket, channels, message)
            elif chat_message.startswith('/user'):
                parameters = chat_message.replace('/user', '', 1).strip().split(" ", 3)
                if len(parameters) != 4:
                    continue

                username = parameters[0]
                real_name = parameters[3]
                try:
                    mode = "{0:b}".format(int(parameters[1]))[::-1]
                    print(mode)
                except ValueError:
                    continue
                mode_i = False
                mode_w = False
                try:
                    if mode[3] == '1':
                        mode_i = True
                except IndexError:
                    pass
                try:
                    if mode[2] == '1':
                        mode_w = True
                except IndexError:
                    pass

                self.user(client_socket, username, real_name, mode_i=mode_i, mode_w=mode_w)
            elif chat_message.startswith('/whois'):
                parameters = chat_message.replace('/whois', '', 1).strip().split(" ")
                if len(parameters) == 1:
                    self.whois(client_socket, parameters)
            elif chat_message.startswith('/who'):
                parameters = chat_message.replace('/who', '', 1).strip().split(" ")
                if len(parameters) == 0:
                    self.who(client_socket, None, False)
                elif len(parameters) == 1:
                    self.who(client_socket, parameters[0], False)
                elif len(parameters) == 2:
                    if parameters[1] == 'o':
                        self.who(client_socket, parameters[0], True)
                    else:
                        self.who(client_socket, parameters[0], False)
                else:
                    continue
            elif chat_message.startswith('/ping'):
                self.ping(client_socket)
            elif chat_message.startswith('/pong'):
                self.pong(client_socket)

               # elif len(parameters) == 2:
                  #  self.whois(client_socket, parameters[1].split(","))
            else:
                self.broadcast_message(chat_message + '\n', name + ': ')

    def quit(self, client_socket, client_address, name=''):
        client_socket.send('/quit'.encode('utf8'))
        client_socket.close()
        del self.clients[client_socket]
        self.broadcast_message(('\n> %s has left the chat room.\n' % name))
        print("Connection with IP address {0} has been removed.\n".format(client_address[0]))

    def list_all_users(self, client_socket, name=''):
        message = "> The users in the chat room are: "
        users_list = ["You" if user == name else user for user in self.clients.values()]
        message = message + ", ".join(users_list) + "\n"
        client_socket.send(message.encode('utf8'))

    def help(self, client_socket):
        client_socket.send(Server.HELP_MESSAGE)

    def away(self, client_socket, away_message=''):
        # User has an away message - set away message
        if away_message.startswith(' '):
            actual_away_message = away_message.replace(' ', '', 1)
            if actual_away_message:
                self.clients_away[client_socket] = actual_away_message
                client_socket.send("> Away message was set\n\n".encode('utf8'))
                return

        # User has not set an away message - remove away message
        del self.clients_away[client_socket]
        client_socket.send("> Away message was unset\n\n".encode('utf8'))

    def server_connect(self, client_socket, target_server, target_port=None):
        try:
            # socket created
            socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_ip_address = socket.gethostbyname(target_server)
            socket1.connect((target_ip_address, target_port))
            # since the socket connected to the server, a sucess message is sent
            success_message = '> Successful connection made to %s:%d\n' % (target_ip_address, target_port)
            client_socket.send(success_message.encode('utf-8'))
        except OSError:
            # this happens if an error occurs and there is no connection
            error_message = '> Cannot make a connection to %s:%d\n' % (target_server, target_port)
            client_socket.send(error_message.encode('utf-8'))

    def server_die(self, client_socket):
        # self.broadcast_message('> Server is shutting down.\n'.encode('utf-8'))
        client_socket.send('> Server is shutting down.\n'.encode('utf-8'))
        self.server_shutdown()

    def server_information(self, client_socket, remote_server):
        if not remote_server:
            server_details = """
                > The server was implemented as version 1,
                for a program for Ortega's Chat assignment
                The server's author is Cesia Bulnes
                It was compiled in 2018.
                \n\n""".encode('utf8')
            client_socket.send(server_details)

    def ison(self, client_socket, nicknames):

        for nickname in nicknames:
            name = self.clients_nicknames[nickname]
            if name in self.clients.values():
                self.online_users.append(name)

        message = ", ".join(self.online_users) + "\n\n"
        client_socket.send(message.encode('utf8'))

    def nick(self, client_socket, new_nickname):
        name = self.clients[client_socket]

        # If user had an old nickname, delete it
        for (nickname, real_name) in self.clients_nicknames.items():
            if name == real_name:
                del self.clients_nicknames[nickname]

        # If someone already had this nickname, notify user
        if new_nickname in self.clients_nicknames:
            client_socket.send("That nickname is already taken!\n\n".encode('utf8'))
            return

        self.clients_nicknames[new_nickname] = name
        client_socket.send("Successfully set new nickname!\n\n".encode('utf8'))

    def password(self, client_socket, set_password):
        name = self.clients[client_socket]
        if name not in self.clients_nicknames.values():
            self.clients_passwords[name] = set_password
            client_socket.send("Successfully set new password!\n\n".encode('utf8'))

    def restart_server(self):
        self.server_shutdown()
        global start_server
        start_server()

    def rules(self, client_socket):
        server_rules = """
                        > The rules of the chat are as follows:
                        Be nice to my grade
                        \n\n""".encode('utf8')
        client_socket.send(server_rules)

    def set_name(self, client_socket, set_the_name):
        self.clients[client_socket] = set_the_name
        client_socket.send("Name is Set\n\n".encode('utf8'))

    def invite(self, client_socket, nickname, channel_name):
        # Channel does not exist
        if channel_name not in self.channel_users:
            client_socket.send("That channel does not exist!\n\n".encode('utf8'))
            return

        # Channel does exist
        try:
            real_name = self.clients_nicknames[nickname]
            for (recipient_socket, recipient_name) in self.clients.items():
                if recipient_name == real_name:
                    invitation_message = "You were invited to join channel %s" % channel_name
                    invitation_message = invitation_message + (",to join simply write /join %s\n" % channel_name)
                    recipient_socket.send(invitation_message.encode('utf8'))
                    client_socket.send("Successfully invited user!\n\n".encode('utf8'))
        except KeyError:
            client_socket.send("User with that nickname cannot be found!\n\n".encode('utf8'))

    def kick(self, client_socket, channel, target_user, comment):
        name = self.clients[client_socket]

        # check if user doing the kicking is an operator
        if name not in self.db.channels[channel]['channelops']:
            client_socket.send("You are not an operator, therefore you cannot kick anyone out.\n\n".encode('utf8'))
            return

        # check if the target user is in the target channel
        if target_user in self.channel_users[channel]:
            self.channel_users[channel].remove(target_user)

            for (nickname, real_name) in self.clients_nicknames.items():
                if real_name == name:
                    if comment:
                        client_socket.send((comment + "\n\n").encode('utf8'))
                    else:
                        client_socket.send("{kicker_nickname}.\n\n".format(
                            kicker_nickname=nickname
                        ).encode('utf8'))
                        return

            if comment:
                client_socket.send((comment + "\n\n").encode('utf8'))
            else:
                client_socket.send("{kicker_nickname}.\n\n".format(
                    kicker_nickname=name
                ).encode('utf8'))

    def userip(self, client_socket, nickname):
        real_name = self.clients_nicknames[nickname]
        ip_address = self.client_ips[real_name]
        print(ip_address[0])
        client_socket.send((ip_address[0] + '\n\n').encode('utf8'))

    def version(self,client_socket):
        client_socket.send("The version of this chat is version 1.0\n\n".encode('utf8'))

    def silence(self, client_socket, parameters):
        name = self.clients[client_socket]
        add_or_remove = parameters[0]  # + or -
        nickname_given = parameters[1]

        if nickname_given in self.clients_nicknames: # nickname of person you're trying to silence

            if name not in self.ignore_list:  # if the nickname hasn't been silence
                if add_or_remove == '+': # you may silence this person

                    self.ignore_list[name] = nickname_given  # add this user to the ignore_list
                    client_socket.send("person was silenced\n\n".encode('utf8'))

            if name in self.ignore_list:  # if the nickname has been silenced
                if add_or_remove == '-': # you may un-silence this person
                    print(add_or_remove)
                    del self.ignore_list[name]   # remove this user from the ignore_list
                    client_socket.send("person was removed from being silenced\n\n".encode('utf8'))

    def join(self, client_socket, channel, password=None):
        ''''
        channel_password = self.db.channels[channel]['password']
        if channel_password and password != channel_password:
            client_socket.send("Channel requires a password and password specified did not match!\n\n".encode('utf8'))
            return
        '''

        username_ofperson = self.clients[client_socket]
        if channel not in self.channel_users:
            self.channel_users[channel] = []

        if username_ofperson not in self.channel_users[channel]:
            self.channel_users[channel].append(username_ofperson)

            print(self.channel_users[channel])
            client_socket.send("Added you to channel {channel}\n\n".format(channel=channel).encode('utf8'))
        else:
            client_socket.send("You're in this channel {channel}\n\n".format(channel=channel).encode('utf8'))

    def oper(self, client_socket, username, password):
        if (username, password) in self.clients_passwords.items():
            print('yo')
            for (channel, name) in self.channel_users.items():
                print('yop')
                if username == name:
                    operator_list = self.db.channels[channel]['channelops']
                    if username not in operator_list:
                        operator_list.append(username)
                        client_socket.send("You are now a channel operator\n\n".encode('utf8'))

    def mode(self, client_socket, nickname, add_remove, modes):
        real_name = self.clients[client_socket]
        if real_name == self.clients_nicknames[nickname]:

            if modes == 'w' or 'i' or 'O' or 'o' or 'r':
                print(modes)
                if modes in self.mode_of_users:
                    users_in_modes = self.mode_of_users[modes]
                    print(users_in_modes)
                    if real_name in users_in_modes:
                        if add_remove == '-':
                            users_in_modes.remove(real_name)
                            client_socket.send("your mode has been removed\n\n".encode('utf8'))
                    elif real_name not in users_in_modes:
                        if add_remove == '+':
                            users_in_modes.append(real_name)
                            client_socket.send("your mode has been added\n\n".encode('utf8'))
                elif modes not in self.mode_of_users:
                    self.mode_of_users[modes] = []
                    users_in_modes = self.mode_of_users[modes]
                    if add_remove == '+':
                        users_in_modes.append(real_name)
                        client_socket.send("your mode has been added\n\n".encode('utf8'))
                    else:
                        client_socket.send("You cannot delete yourself from a mode that doesnt exist\n\n".encode('utf8'))
        else:
            client_socket.send("You cannot change someone else's mode\n\n".encode('utf8'))

    def wallops(self, client_socket, wallops_message):
        usernames_wallops = self.mode_of_users['w']
        print(usernames_wallops)
        usernames_operators = self.mode_of_users['o']
        print(usernames_operators)
        wallops_and_operators = usernames_wallops or usernames_operators
        for username in wallops_and_operators:
            for (user_socket, current_username) in self.clients.items():
                if username == current_username:
                    user_socket.send((wallops_message + '\n\n').encode('utf8'))
        client_socket.send('Your message has been sent to users users with modes operators and wallops\n\n'.encode('utf8'))

    def topic(self, client_socket, channel, topic_message):
        if topic_message is None:
            topic = self.channel_topic[channel]

            client_socket.send(('the topic in {channel} is {topic}' + '\n\n').format(channel=channel,topic=topic).encode(
                'utf8'
            ))
        else:
            self.channel_topic[channel] = topic_message
            client_socket.send('topic was changed in {channel} to {topic_message}\n\n'.format(
                channel=channel,
                topic_message=topic_message
            ).encode('utf8'))

    def time(self, client_socket, target):
            y = time.strftime("%I:%M:%S")
            client_socket.send(y.encode('utf8'))

    def userhost(self,client_socket, nickname_list):
        x = len(nickname_list)
        print(x)
        i=0
        while i < x:
            for nickname in nickname_list:
                if nickname in self.clients_nicknames:
                    print(nickname)
                    real_name = self.clients_nicknames[nickname]
                    print(real_name)
                    ip = self.client_ips[real_name]
                    print(ip[0])
                    ip_address = ip[0]
                    user_name = self.client_usernames[real_name]
                    print(user_name)
                    client_socket.send('The user with the nickname {nickname} ,'
                                       ' has the real name of {real_name} , ip address: {ip_address}, '
                                       'username: {user_name}\n\n'.format(
                                        nickname=nickname, real_name=real_name,
                                        ip_address=ip_address, user_name=user_name).encode('utf8'))
            i = i+ 1

    def kill(self, client_socket, nickname, comment):
        my_real_name = self.clients[client_socket]
        if my_real_name in self.mode_of_users['o']:
            if nickname in self.clients_nicknames:
                kill_person_name = self.clients_nicknames[nickname]
                for client_socket1 in self.clients:
                    if self.clients[client_socket1] + ': ' == kill_person_name:
                        client_socket1.close()
                        del self.clients[client_socket1]
                        self.broadcast_message(('\n> %s has been killed from the chat room because %s .\n' % nickname,
                                                comment))

    def privmsg(self, client_socket, msgtarget, message):
        print(msgtarget)
        print(self.channel_users.values())

        if msgtarget not in self.channel_users.values():
            channel = 'me' + msgtarget
            if channel not in self.channel_users:
                self.channel_users[channel] = []
            if msgtarget not in self.channel_users[channel]:
                self.channel_users[channel].append(msgtarget)

                print(self.channel_users[channel])
                for (user_socket, user_name) in self.clients.items():
                    if msgtarget == user_name:  # name
                        user_socket.send((message + "\n\n").encode('utf8'))
                        print('done')
                        return
        if msgtarget in self.channel_users.keys():
            print(self.channel_users[msgtarget])
            users = self.channel_users[msgtarget]
            print(users)
            for user in users:
                for (user_socket, user_name) in self.clients.items():
                    if user == user_name:
                        user_socket.send((message + "\n\n").encode('utf8'))
                        print('hi')
                        return


    def notice(self, msgtarget, message):
        # msgtarget = channel_name
        if self.channel_users[msgtarget] is not None:
            print(self.channel_users[msgtarget])
            users = self.channel_users[msgtarget]
            print(users)
            for user in users:
                for (user_socket, user_name) in self.clients.items():
                    if user == user_name:
                        user_socket.send((message + "\n\n").encode('utf8'))
                        print('hi')
                        return

    def list(self, client_socket, channels):
        list_message = ""
        if channels is None:
            print(self.channel_topic.items())
            for (channel, topic) in self.channel_topic.items():
                list_message = list_message + 'channel: ' + channel + ',' + 'topic: ' + topic + '\n'
            client_socket.send('Channels Information: {list_message}\n\n'.format(list_message=list_message).encode('utf8'))
        else:
            for channel in channels:
                if channel in self.channel_topic:
                    topic = self.channel_topic[channel]
                    list_message = list_message + 'channel:' + channel + ',' + 'topic' + topic + '\n'
            client_socket.send('Channels Info: {list_message}\n\n'.format(list_message=list_message).encode('utf8'))

    def knock(self, client_socket, channel_target, message):
        name = self.clients[client_socket]
        if self.channel_users[channel_target] is not None:
            print(self.channel_users[channel_target])
            users = self.channel_users[channel_target]
            print(users)
            for user in users:
                for (user_socket, user_name) in self.clients.items():
                    if user == user_name:
                        user_socket.send(('{name} is requesting to join {channel_target} because : ' + '"'+ message +
                                          '"' + "\n\n")
                                         .format(name=name,channel_target = channel_target).encode('utf8'))
                        print('hi')
                        return
        '''
        if self.db.channels.get(channel_target, None) is not None:
            users = self.channel_users[channel_target]
            for user in users:
                for (user_socket, user_name) in self.clients.items():
                    if user == user_name:
                        user_socket.send((message + "\n\n").encode('utf8'))
                        client_socket.send(('your requested invitation to %s has been sent\n\n' % channel_target).encode(
                            'utf8'
                        ))
                        return
        '''

    def part(self, client_socket, channels, message):
        real_name = self.clients[client_socket]
        if message is None:
            message = real_name
            for (nickname, name) in self.clients_nicknames:
                if real_name == name:
                    message = nickname

        for channel in channels:
            channel_user = self.channel_users[channel]
            print(channel_user)
            if real_name in channel_user:
                channel_user.remove(real_name)
                for user in self.channel_users[channel]:
                    for (user_socket, user_name) in self.clients.items():
                        if user == user_name:
                            user_socket.send('User {user} has left channel {channel} with message: {message}\n\n'.format(
                                user=real_name,
                                channel=channel,
                                message=message
                            ).encode('utf8'))
                self.channel_users[channel] = channel_user
            client_socket.send('You have parted channel {channel}\n\n'.format(
                channel=channel
            ).encode('utf8'))

    def user(self, client_socket, username, real_name, mode_i, mode_w):
        print(real_name)
        print(self.clients[client_socket])
        if real_name == self.clients[client_socket]:
            print(real_name)
            client_address = self.client_ips[real_name]
            print(client_address)
            self.client_usernames[real_name] = []
            self.db.users[real_name] = []
            self.client_usernames[real_name].append(username)
            print(self.client_usernames[real_name])
            self.db.users[real_name].append(username)
            x = self.clients[client_socket]
            print(x)

            if mode_i == 'i':
                    mode_i_users = self.mode_of_users.get('i', [])
                    mode_i_users.append(real_name)
                    self.mode_of_users['i'] = mode_i_users
                    print(mode_i_users)
            if mode_w == 'w':
                    mode_w_users = self.mode_of_users.get('w', [])
                    mode_w_users.append(real_name)
                    self.mode_of_users['w'] = mode_w_users
                    print(mode_w_users)
            client_socket.send('You have successfully been set as a user\n\n'.encode('utf8'))

    def who(self, client_socket, name, iso):

        if name is None:
            message = ""
            for (_, some_name) in self.clients.items():
                if some_name not in self.mode_of_users.get('i', []):
                    print(some_name)
                    message += "User {user}\n".format(user=some_name)
            client_socket.send((message + "\n\n").encode('utf-8'))
            return

        for (socket, some_name) in self.clients.items():
            if some_name == name:
                if iso is True:
                    if name in self.mode_of_users.get('o', []):
                        client_socket.send("User {user}\n\n".format(user=name).encode('utf8'))
                        return
                    else:
                        client_socket.send("User is not an operator, try again\n\n".encode('utf8'))
                        return
                else:
                    client_socket.send("User {user}\n\n".format(user=name).encode('utf8'))
                    return
        else:
            client_socket.send("User does not exist\n\n".encode('utf8'))

    def ping(self, client_socket):
        client_socket.send('PONG\n\n'.encode('utf8'))

    def pong(self, client_socket):
        client_socket.send('PING\n\n'.encode('utf8'))

    def whois(self, client_socket, nickname_list):
        message = ""
        for nickname in nickname_list:
            message += "Info about {nickname}\n".format(nickname=nickname)
            if nickname in self.clients_nicknames:
                real_name = self.clients_nicknames[nickname]
                message += "Real name: {real_name}\n".format(real_name=real_name)

                username = self.client_usernames.get(real_name, None)
                if username:
                        message += "Username: {username}\n".format(username=username)
                else:
                    message += "No username set\n"

                member_of_channels = ""
                for (channel, user_list) in self.channel_users.items():
                    if real_name in user_list:
                        print(channel)
                        member_of_channels= member_of_channels + channel
                        print(member_of_channels)
                    member_of_channels = member_of_channels + ","
                message += "Member of channels: {channels}\n".format(
                            channels=member_of_channels
                            )
                message += "End Info about {nickname}".format(nickname=nickname)
                client_socket.send((message + "\n\n").encode('utf8'))


def main():
    argument_parser = argparse.ArgumentParser("IRC Chat Server")
    argument_parser.add_argument(
        "-configuration",
        help="Configuration File Path",
        type=str,
        default=os.getcwd() + "/conf/chatserver.conf"
    )
    argument_parser.add_argument(
        "-port",
        help="Port for the IRC Chat Server",
        type=str,
        required=True
    )
    argument_parser.add_argument(
        "-db",
        help="Path for folder containing txt files",
        type=str,
        default=None
    )

    arguments = argument_parser.parse_args()
    config_object = utils.get_config_from_file(getattr(arguments, "configuration"))

    # Get the Port and DB Path setting from either the ArgumentParser instance - if it doesn't
    # exist there, default to config object
    def get_from_args_or_config(arguments, config_object, key):
        value = getattr(arguments, key)
        if value is None:
            if key == "db":
                key = "dbpath"
            value = config_object.get(key)

        return value
    try:
        port = int(get_from_args_or_config(arguments, config_object, "port"))
    except ValueError:
        port = None
    if port is None:
        print("Port is not provided as an argument or config, or is invalid")
        return
    db_path = get_from_args_or_config(arguments, config_object, "db")
    if db_path is None or not os.path.exists(db_path):
        print("DB path is not provided as an argument or config, or doesn't exist")
        return

    global start_server
    start_server = start_server_closure(Server(
        port=port,
        db=DB(db_path=db_path)
    ))
    start_server()


if __name__ == "__main__":
    main()
