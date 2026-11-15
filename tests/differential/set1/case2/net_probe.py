import socket, sys
try:
    socket.create_connection(("1.1.1.1", 53), 2)
    print("NET_REACHED")
    sys.exit(0)
except Exception as e:
    print("NET_BLOCKED", type(e).__name__)
    sys.exit(2)
