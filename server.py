# -*- encoding=utf-8 -*-
import json
import socket
from processor.net.parser import  *
from processor.tran.parser import UDPParser, TCPParser


class Server:
    def __init__(self):
        # 工作协议类型、套接字类型、工作协议类型
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        # 更改为自己的主机IP
        self.ip = '10.133.152.167'
        self.port = 8888
        self.sock.bind((self.ip, self.port))
        # 混杂模式
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def loop_serve(self):
        for i in range (0, 10):
            # 接收数据报
            packet, addr = self.sock.recvfrom(65535)
            # 生成处理结果
            result = self.process(packet)
            # 获取结果
            result = json.dumps(
                result,
                indent=4
            )
            print(result)
        pass

    def process(self, packet):
        headers = {
            'network_header': None,
            'transport_header': None
        }

        ip_header =  IPParser.parse(packet)
        headers['network_header'] = ip_header
        if ip_header['protocol'] == 17:
            udp_header = UDPParser.parse(packet)
            headers['udp_header'] = udp_header
        elif ip_header['protocol'] == 6:
            tcp_header = TCPParser.parse(packet)
            headers['tcp_header'] = tcp_header
        return headers


if __name__ == '__main__':
    server = Server()
    server.loop_serve()
