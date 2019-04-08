import socket
import threading


class PortScan:

    def __init__(self, host, ports):
        self.threads = 25
        self.host = host
        self.ports = ports
        self.lock = threading.BoundedSemaphore(value=self.threads)

    def port_scanner(self, host, ports):
        openports = []
        self.lock.acquire()
        for port in ports:
            try:
                connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                connect.settimeout(2)
                result = connect.connect_ex((host, int(port)))
                if result == 0:
                    openports.append(port)
                connect.close()
            except Exception as e:
                print(e)
                pass
        self.lock.release()
        return openports

    def process(self):
            ports = self.port_scanner(self.host, self.ports)
            return ports
