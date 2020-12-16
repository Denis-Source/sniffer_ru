import struct

from packets.ipv4 import IPv4Packet


class UDPPacket(IPv4Packet):
    """
    Клас пакета UDP
    Аргументы:
    raw_data - в формате потока битов.
    Наследует класс IPv4Packet.
    Атрибуты, которые унаследованы:
        id_counter : счетчик, используеммый для подсчета количества пакетов;
        proto : версия протокола в формате int;
        proto_str : версия протокола в формате str;
        ttl : время жизни пакета int;
        src : адрес источника пакета в формате IPv4 str;
        target : афдрес цели пакета в формате IPv4 str;
        data : пакет в формате bytes;
        time : время захвата пакета в формате asctime str;

    Атрибуты:
        src_port : порт источника int;
        dest_port : порт назначения int;
        size : размер данных в битах int;
        payload : данные, что являются полезной нагрузкой пакета в формате потока битов bytes;

    """

    def __init__(self, raw_data):
        IPv4Packet.__init__(self, raw_data)
        IPv4Packet.id_counter -= 1
        self.src_port, self.dest_port, self.size = struct.unpack("! H H 2x H", raw_data[:8])

    def __str__(self):
        """
        Превращение пакета в форму, удобную для чтения

        Возрвращает строку, имеющюю следующий формат:
            Ethernet Packet #1 	Time: Tue Dec 8 00:01:26 2019
            TTL: 128 Protocol: UDP
            Source: 192.168.0.0:65535, Destination: 255.255.255.255:80
            Data:
            E3 41 01 BB 00 24 03 6F 40 A3 EA 7D C4 C0 51 46 DF 07

        :return: str
        """
        return f"\nEthernet Packet #{self.id_counter} \tTime: {self.time}\n" \
               f"TTL: {self.ttl} Protocol: {self.proto_str}\n" \
               f"Source: {self.src}:{self.src_port}, Destination: {self.target}:{self.dest_port}\n" \
               f"Data: \n{IPv4Packet.bytes_to_hex(self.payload)}"
