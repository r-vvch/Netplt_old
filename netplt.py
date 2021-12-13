import argparse
import math
import pyshark
import matplotlib.pyplot as plt
from datetime import datetime


class PacketInfo:
    def __init__(self, stream, length, time_relative):
        self.stream = int(stream)
        self.length = float(length)
        self.time_relative = float(time_relative)

    def __str__(self):
        return "% s % s % s" % (self.stream, self.length, self.time_relative)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build graphs for TCP steams')
    parser.add_argument('pcap_file_name', type=str, help='Path to input pcap file')
    parser.add_argument('--save', '-s', action='store_false', help='Save graphs')
    args = parser.parse_args()

    pcap = pyshark.FileCapture(args.pcap_file_name, display_filter="tcp")

    packet_storage = []

    max_stream = 0
    for packet in pcap:
        stream_num = int(packet.tcp.stream)
        if stream_num > max_stream:
            max_stream = stream_num
        try:
            packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet.tcp.time_relative))
        except IndexError:
            packet_storage.append([])
            while len(packet_storage) < stream_num + 1:
                packet_storage.append([])
            packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet.tcp.time_relative))

    plt.rcParams["figure.figsize"] = (9, math.ceil(max_stream / 3) * 3)
    for stream_packets in packet_storage:
        times = []
        lengths = []
        stream = stream_packets[0].stream
        for packet in stream_packets:
            times.append(float(packet.time_relative))
            lengths.append(packet.length)
        plt.subplot(max_stream // 3 + 1, 3, stream + 1)
        plt.plot(times, lengths)
        plt.title(stream)
        plt.xlabel('time')
        plt.ylabel('length')
        plt.xticks(rotation=45)
    plt.tight_layout()
    now = datetime.now()
    now.replace(microsecond=0)
    plt.savefig('streams_graph_' + now.isoformat(sep='_', timespec='seconds') + '.png')
    # plt.show()
