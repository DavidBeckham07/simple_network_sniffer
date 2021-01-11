import struct


def data2str(data):
    l = len(data)
    data = struct.unpack(l * 'B', data)
    string = ''
    for ch in data:
        if ch >= 122 or ch < 32:
            string += '.'
        else:
            string += chr(ch)
    return string


class UDPParser:
    '''
    1. 16位源端口 16位目的端口
    2. 16位UDP长度 16位校验和
    '''

    @classmethod
    def parse_udp_header(cls, udp_header):
        udp_header = struct.unpack(">HHHH", udp_header)
        return {
            'src_port': udp_header[0],
            'dst_port': udp_header[1],
            'udp_length': udp_header[2],
            'udp_checksum': udp_header[3]
        }
        pass

    @classmethod
    def parse(cls, packet):
        udp_header = packet[20: 20 + 8]
        result = cls.parse_udp_header(udp_header)
        data = data2str(packet[40:])
        result['data'] = data
        return result

    pass


class TCPParser:
    @classmethod
    def parse(cls, package):
        # IP首部20字节
        result = cls.parse_tcp_header(package[20:40])
        data = data2str(package[40:])
        result['data'] = data
        return result

    @classmethod
    def parse_tcp_header(cls, tcp_header):
        '''
        TCP header 结构：
        1. 16位源端口 16位目的端口
        2. 序列号
        3. 确认号
        4. 4位数据偏移 6位保留字段 6位标志位 窗口大小
        5. 16位校验和 16位紧急指针
        :return:
        '''
        line1 = struct.unpack('>HH', tcp_header[:4])
        src_port = line1[0]
        dst_port = line1[1]

        line2 = struct.unpack(">L", tcp_header[4: 8])
        seq_num = line2[0]

        line3 = struct.unpack('>L', tcp_header[8:12])
        ack_num = line3[0]

        line4 = struct.unpack('>BBH', tcp_header[12: 16])
        data_offet = line4[0] >> 4
        flags = line4[1] & int('00111111', 2)
        FIN = flags & 1
        SYN = (flags >> 1) & 1
        RST = (flags >> 2) & 1
        PSH = (flags >> 3) & 1
        ACK = (flags >> 4) & 1
        URG = (flags >> 5) & 1
        win_size = line4[2]

        line5 = struct.unpack(">HH", tcp_header[16: 20])
        checksum = line5[0]
        urg_point = line5[1]

        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'data_offset': data_offet,
            'flag': {
                'FIN': FIN,
                'SYN': SYN,
                'RST': RST,
                'PSH': PSH,
                'ACK': ACK,
                'URG': URG
            },
            'win_size': win_size,
            'checksum': checksum,
            'urg_point': urg_point
        }
