import socket
import sys
import threading

import socket
import sys
import threading

class Server:
    SERVER_CONFIG = {"BACKLOG": 15}

    HELP_MESSAGE = """> The list of commands available are:

/quit - Exits the program.
/list - Lists all the users in the chat room.\n\n""".encode('utf8')

    def __init__(self, host=socket.gethostbyname('localhost'), port=50000, allowReuseAddress=True):
        self.host = host
        self.port = port
        self.address = (self.host, self.port)
        self.clients = {}
        self.clientThreadList = []

        try:
            self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as errorMessage:
            sys.stderr.write("Failed to initialize the server. Error - %s\n", errorMessage)
            raise

        if allowReuseAddress:
            self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.serverSocket.bind(self.address)
        except socket.error as errorMessage:
            sys.stderr.write('Failed to bind to ' + self.address + '. Error - %s\n', errorMessage[1])
            raise

    def listen_thread(self, defaultGreeting="\n> Welcome to our chat app!!! What is your name?\n"):
        while True:
            print("Waiting for a client to establish a connection\n")
            clientSocket, clientAddress = self.serverSocket.accept()
            print("Connection established with IP address {0} and port {1}\n".format(clientAddress[0], clientAddress[1]))
            clientSocket.send(defaultGreeting.encode('utf8'))
            clientThread = threading.Thread(target=self.client_thread, args=(clientSocket, clientAddress))
            self.clientThreadList.append(clientThread)
            clientThread.start()

        for thread in self.clientThreadList:
            if thread.is_alive():
                thread.join()

    def start_listening(self):
        self.serverSocket.listen(Server.SERVER_CONFIG["BACKLOG"])
        listenerThread = threading.Thread(target=self.listen_thread)
        listenerThread.start()
        listenerThread.join()

    def client_thread(self, clientSocket, clientAddress, size=4096):
        name = clientSocket.recv(size).decode('utf8')
        welcomeMessage = '> Welcome %s, type /help for a list of helpful commands.\n\n' % name
        clientSocket.send(welcomeMessage.encode('utf-8'))
        chatMessage = '\n> %s has joined the chat!\n' % name
        self.broadcast_message(chatMessage)
        self.clients[clientSocket] = name

        while True:
            chatMessage = clientSocket.recv(size).decode('utf8')

            if chatMessage == '/quit':
                self.quit(clientSocket, clientAddress, name)
                break
            elif chatMessage == '/list':
                self.list_all_users(clientSocket, name)
            elif chatMessage == '/help':
                self.help(clientSocket)
            else:
                self.broadcast_message(chatMessage + '\n' , name + ': ')

    def quit(self, clientSocket, clientAddress, name=''):
        clientSocket.send('/quit'.encode('utf8'))
        clientSocket.close()
        del self.clients[clientSocket]
        self.broadcast_message(('\n> %s has left the chat room.\n' % name))
        print("Connection with IP address {0} has been removed.\n".format(clientAddress[0]))

    def list_all_users(self, clientSocket, name=''):
        message = "> The users in the chat room are: "
        users_list = ["You" if user==name else user for user in self.clients.values()]
        message = message + ", ".join(users_list) + "\n"
        clientSocket.send(message.encode('utf8'))

    def help(self, clientSocket):
        clientSocket.send(Server.HELP_MESSAGE)

    def server_shutdown(self):
        print("Shutting down chat server.\n")
        self.serverSocket.shutdown(socket.SHUT_RDWR)
        self.serverSocket.close()

    def broadcast_message(self, message, name=''):
        for socket in self.clients:
            if self.clients[socket] + ': ' != name:
                socket.send((name + message).encode('utf8'))
            else:
                socket.send(('You: ' + message).encode('utf8'))

def main():
    chatServer = Server()

    print("\nListening on port " + str(chatServer.port))
    print("Waiting for connections...\n")

    chatServer.start_listening()
    chatServer.server_shutdown()

if __name__ == "__main__":
    main()
