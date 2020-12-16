import time
import struct


class IPv4Packet(object):
    """
    Класс пакета, который используется в протоколах IPv4.
    Аргументы:
    raw_data - в формате потока битов

    Атрибуты:
        id_counter : счетчик, используеммый для подсчета количества пакетов
        proto : версия протокола в формате int
        proto_str : версия протокола в формате str
        ttl : время жизни пакета
        src : адрес источника пакета в формате IPv4
        target : афдрес цели пакета в формате IPv4
        time : время захвата пакета в формате asctime
        data : пакет в формате bytes
        payload : данные, что являются полезной нагрузкой пакета в формате потока битов

    Статические методы:
        ipv4_addr_conv(addr) :
        Преобразовывает масив чисел в адрес формата IPv4 (255.255.255.255)
        protocol_ver(proto_num) :
        Преобразовывает число в название протокола
        bytes_to_hex(raw_data, rows=80) :
        Преобразовывает масив битов в шестнадцатеричный код удобный для чтения
        по одному байту через пробел
    """

    id_counter = -1  # счетчик пакетов

    def __init__(self, raw_data):
        IPv4Packet.id_counter += 1

        self.data = raw_data
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4

        self.ttl, self.proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
        self.src = self.ipv4_addr_conv(src)
        self.target = self.ipv4_addr_conv(target)
        self.payload = raw_data[header_length:]
        self.id_counter = IPv4Packet.id_counter
        self.proto_str = self.protocol_ver(self.proto)
        self.time = time.asctime()

    def __str__(self):
        """
        Превращение пакета в форму, удобную для чтения

        :return: str
        Возрвращает строку, имеющюю следующий формат:
            Ethernet Frame: #1146 Time: 	Sun Dec  8 16:35:40 2019
            TTL: 1 Protocol: IGMP
            Source: 192.168.0.104, Destination: 224.0.0.2
            Data:
            17 00 08 03 E0 00 00 FC
        """
        return f"\nEthernet Frame: #{self.id_counter} Time: \t{self.time}\n" \
               f"TTL: {self.ttl} Protocol: {self.proto_str}\n" \
               f"Source: {self.src}, Destination: {self.target}\n" \
               f"Data: \n{IPv4Packet.bytes_to_hex(self.payload)}"

    @staticmethod
    def ipv4_addr_conv(addr):
        """
        Статический метод, который преобразовывает масив чисел в адрес формата IPv4 (255.255.255.255)

        :param addr: list
        :return: str
        """
        return ".".join(map(str, addr))

    @staticmethod
    def protocol_ver(proto_num):
        """
        Статический метод, который преобразовывает число в название протокола

        :param proto_num: int
        :return: str
        """
        if proto_num == 1:
            return "ICMP"
        elif proto_num == 2:
            return "IGMP"
        elif proto_num == 6:
            return "TCP"
        elif proto_num == 17:
            return "UDP"
        else:
            return f"OTHER ({proto_num})"

    @staticmethod
    def bytes_to_hex(raw_data, rows=80):
        """
        Статический метод, который преобразовывает масив битов в шестнадцатеричный код удобный для чтения
        по одному байту через пробел
        количество байтов на строчку указывается переменной rows
        пример выхода:

        4E 71 00 00 17 03 03 08 1B 16 2A 80 7C 04 0E 2E 4C E4 BE AD 6D ED 37 3F 99 94 B9 96 06 DE CA 48 6D 66 C4 7B 6F
        3A 20 72 F4 B7 C2 E8 30 E9 FD 3E 61 75 2D 70 C0 DB D3 94 8E E1 BE F3 AF 6B 91 AC 78 2A 32 FC CA AF DF E7 B2 40
        0B 64 01 64 F8 7E 5E 92 A8 54 37 4F 32 DA 7D AA B8 D4 DD 7B 1E 33 5C B0 9B 79 CD C3 A1 8E 48 5C 52 15 96 50 8E
        84 8E 32 05 5D F5 C0 68 E2 F7 EA 1A 46 D3 5E 6A 96 37

        :param raw_data: bytes
        :param rows: int
        :return: str
        """

        data = raw_data.hex().upper()
        return_str = ""
        for i in range(len(data)):
            return_str += data[i]
            if i % 2 == 1:
                return_str += " "
            if i % rows == rows - 1:
                return_str += "\n"
        return return_str
