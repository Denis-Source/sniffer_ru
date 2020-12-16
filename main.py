"""Сниффер

Данная программа позволяет захватывать все датаграммы, которые используются в протоколах TCP/IP.
Использует следующие модули:
    socket для работы с програмными интерфейсами;
    struct для декодирования пакетов;
    time для фиксации времени захвата пакетов.
Состоит из следующих классов:
    IPv4Packet;
    TCPPacket;
    UDPPacket;
    Sniffer.
"""

from sniffer import Sniffer

if __name__ == '__main__':
    sniffer = Sniffer()
    sniffer.sniff(is_inf=True, to_print=True)
