# netcentric-chat

We are making a IRCish server, time to have fun

## Commands we need to implement

- [ ] AWAY
The /away command marks you as away with the server. Using the away with no parameters will unset your away status. Even though /away uses IRC to mark you as away; this command also stores the away message and the time left internally. 
- [ ] CONNECT
Obv connect with the following params

```
-
h hostname 
-
u username
-
p 
server port
-
c config
uarion
file
-
t  
run test file; 
-
t test2.txt
-
L log_file_name
(for log messages) 
```
- [ ] DIE (Server Side)
Instructs the server to shut down. This command may only be issued by IRC server operators.
- [ ] HELP
Slash command that shows help
- [ ] INFO
Returns information about the <target> server, or the current server if <target> is omitted.
- [ ] INVITE
Invites <nickname> to the channel <channel>.
- [ ] ISON
Queries the server to see if the clients in the space-separated list <nicknames> are currently on the network.
- [ ] JOIN
Makes the client join the channels in the comma-separated list <channels>, specifying the passwords, if needed, in the comma-separated list <keys>.
- [ ] KICK (Server side)
Forcibly removes <client> from <channel>.
- [ ] KILL (Server Side)
Forcibly removes <client> from the network.
- [ ] KNOCK
Sends a NOTICE to an invitation-only <channel> with an optional <message>, requesting an invite. 
- [ ] LIST
Lists all channels on the server
- [ ] MODE
The MODE command is dual-purpose. It can be used to set both user and channel modes.
- [ ] NOTICE
This command works similarly to PRIVMSG, except automatic replies must never be sent in reply to NOTICE messages
- [ ] PART (Server side)
Causes a user to leave the channels in the comma-separated list <channels>
- [ ] OPER
Authenticates a user as an IRC operator on that server/network
- [ ] PASS
Sets a connection password.
- [ ] PING
Tests the presence of a connection.
- [ ] PONG
This command is a reply to the PING command and works in much the same way
- [ ] PRIVMSG
Sends <message> to <msgtarget>, which is usually a user or channel
- [ ] QUIT
Disconnects the user from the server.
- [ ] RESTART (Server Side)
Restarts the server
- [ ] RULES
Shows the rules
- [ ] SETNAME
Sets the new real name
- [ ] SILENCE
Adds or removes a host mask to a server-side ignore list that prevents matching users from sending the client messages. More than one mask may be specified in a space-separated list, each item prefixed with a "+" or "-" to designate whether it is being added or removed. Sending the command with no parameters returns the entries in the client’s ignore list.
- [ ] TIME
Shows time
- [ ] TOPIC
Shows the channel topic
- [ ] USER
This command is used at the beginning of a connection to specify the username, hostname, real name and initial user modes of the connecting client
- [ ] USERHOST
Returns a list of information about the nicknames specified.
- [ ] USERIP
Gets the IP of a specified user
- [ ] USERS
Returns a list of users and information about those users in a format like UNIX
- [ ] VERSION
Runs the version of the server
- [ ] WALLOPS
Sends <message> to all operators connected to the server
- [ ] WHO
Returns a list of users who match <name>, with -o flag, shows all the ops
- [ ] WHOIS (Can be Server-Side)
Returns information about the comma-separated list of nicknames masks <nicknames>

### Extra Credit

- [ ] ADMIN
- [ ] CNOTICE
- [ ] CPRIVMSG
- [ ] ERROR
- [ ] LUSERS
- [ ] MOTD
- [ ] NAMES
- [ ] SERVER
- [ ] SERVICE
- [ ] SERVLIST
- [ ] SQUIT
- [ ] SQUERY
- [ ] SUMMON
- [ ] TRACE
- [ ] WATCH
- [ ] WHOWAS