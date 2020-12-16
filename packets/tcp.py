import struct

from packets.ipv4 import IPv4Packet


class TCPPacket(IPv4Packet):
    """
    Клас пакета TCP
    Аргументы:
    raw_data - в формате потока битов.
    Наследует класс IPv4Packet.
    Атрибуты, которые унаследованы:
        id_counter : счетчик, используеммый для подсчета количества пакетов;
        proto : версия протокола в формате int;
        proto_str : версия протокола в формате str;
        ttl : время жизни пакета;
        src : адрес источника пакета в формате IPv4;
        target : афдрес цели пакета в формате IPv4;
        data : пакет в формате bytes;
        time : время захвата пакета в формате asctime.

    Атрибуты:
        payload : данные, что являются полезной нагрузкой пакета в формате потока битов;
        src_port : порт источника;
        dest_port : порт назначения;
        sequence;
        acknowledgement;
        Флаги:
            flag_urg;
            flag_ack;
            flag_psh;
            flag_rst;
            flag_syn;
            flag_fin.
    """

    def __init__(self, raw_data):
        IPv4Packet.__init__(self, raw_data)
        IPv4Packet.id_counter -= 1
        (self.src_port, self.dest_port, self.sequence, self.acknowledgement, offset_reserved_flags) = struct.unpack(
            "! H H L L H",
            raw_data[:14])
        self.offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.payload = raw_data[self.offset:]

    def __str__(self):
        """
        Превращение пакета в форму, удобную для чтения

        Возрвращает строку, имеющюю следующий формат:
            Ethernet Frame: #1 	Time: Tue Dec 8 00:01:28 2019
            TTL: 57 Protocol: TCP
            Source: 255.255.255.255:80, Destination: 192.168.0.0:65535
            Flags: urg: 0, ack: 1, fsh: 1, rst 1, syn: 1, fin: 1
            Data:
            17 03 03 00 27 73 02 12 E6 F3 6F 3E 1E 43 F9 7B 1B C7 9C D6 35
        :return: str
        """

        return f"\nEthernet Frame: #{self.id_counter} \tTime: {self.time}\n" \
               f"TTL: {self.ttl} Protocol: {self.proto_str}\n" \
               f"Source: {self.src}:{self.src_port}, Destination: {self.target}:{self.dest_port}\n" \
               f"Flags: urg: {self.flag_urg}, ack: {self.flag_ack}, fsh: {self.flag_psh}, " \
               f"rst {self.flag_rst}, syn: {self.flag_rst}, fin: {self.flag_fin}\n" \
               f"Data: \n{IPv4Packet.bytes_to_hex(self.payload)}"
