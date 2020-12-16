import socket
import struct

from packets.ipv4 import IPv4Packet
from packets.udp import UDPPacket
from packets.tcp import TCPPacket


class Sniffer(object):
    """
    Класс Сниффер
    Используется для захвата пакетов протокола IPv4

    Атрибуты:
        host : IP-адрес формата IPv4, который используется для захвата пакетов;
        host_name : имя компьютера, что используется для передачи пакетов;
        socket : класс библеотеки socket.

    Методы:
        sniff_once;
        sniff;
        save_packets;
        save_packets.

    Статические методы:
        get_mac_addr;
        enthernet_frame.
    """

    def __init__(self, ip="AUTO"):
        if ip == "AUTO":
            self.host = socket.gethostbyname_ex(socket.gethostname())[-1][-1]
            self.host_name = socket.gethostbyname_ex(socket.gethostname())[0]
        else:
            self.host = ip
            self.host_name = "unknown"
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.socket.bind((self.host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    @staticmethod
    def get_mac_addr(bytes_addr):
        """
        Статический метод, который преобразовывает масив битов в строку МАС-адреса (AA:BB:CC:DD:EE).

        :param bytes_addr: bytes
        :return: str
        """
        bytes_str = map("{:02x}".format, bytes_addr)
        return ":".join(bytes_str).upper()

    @staticmethod
    def enthernet_frame(data):
        """
        Статический метод, который преобразовывает масив битов в МАС-адрес источника и назначения, протокол передачи.

        :param data: bytes
        :return: str, str, int, bytes
        """
        dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
        return Sniffer.get_mac_addr(dest_mac), Sniffer.get_mac_addr(src_mac), socket.htons(proto), data[:14]

    def sniff_once(self, to_print):
        """
        Захватывает один пакет, возвращает пакет класса IPv4Packet

        :param to_print: bool выводить ли пакет на экран
        :return: IPv4Packet
        """
        packet, addr = self.socket.recvfrom(65536)
        datagram = IPv4Packet(packet)

        if datagram.proto_str == "TCP":
            datagram = TCPPacket(packet)
        if datagram.proto_str == "UDP":
            datagram = UDPPacket(packet)
        if to_print:
            print(datagram)
        return datagram

    def sniff(self, num_of_packets=1, is_inf=False, to_print=False):
        """
        Захватывает пакеты

        :param num_of_packets: int количество захватываемых пакетов
        :param is_inf: bool захватывать ли неограниченое количество пакетов
        :param to_print: bool выводить ли пакеты на экран
        :return: None
        """
        if to_print:
            print(f"Sniffing {self.host_name} at {self.host}:")
        if is_inf:
            while True:
                self.sniff_once(to_print)
        else:
            for i in range(num_of_packets):
                self.sniff_once(to_print)

    def save_packets(self, file_name="test.txt", num_of_packets=1, is_inf=False, to_print=False):
        """
        Захватывет пакеты, сохраняет их в текстовый файл с указаным именем

        :param file_name: str название файла
        :param num_of_packets: int количество захватываемых пакетов
        :param is_inf: bool захватывать ли неограниченое количество раз
        :param to_print: bool выводить ли пакеты на экран
        :return: None
        """
        if to_print:
            print(f"Saving packets from {self.host_name} at {self.host}:")
        file = open(file_name, "w")
        file.write(f"Saved packets from {self.host_name} at {self.host}:\n")
        file.close()
        if is_inf:
            while True:
                datagram = self.sniff_once(to_print)
                file = open(file_name, "a")
                file.write(str(datagram))
                file.write("\n")
                file.close()
        else:
            for i in range(num_of_packets):
                datagram = self.sniff_once(to_print)
                file = open(file_name, "a")
                file.write(str(datagram))
                file.write("\n")
                file.close()

    def domain_hunt(self):
        while True:
            packet = self.sniff_once(to_print=False).payload.decode("utf-8", "ignore")
            alpha = "abcdefghijklmnopqrstuvwxyz -.\n\t"
            packet_str = ""
            for i in packet:
                if i in alpha:
                    packet_str += i
            print(packet_str)
