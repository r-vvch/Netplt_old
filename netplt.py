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
    parser.add_argument('num_intervals', nargs='?', type=int, default=10, help='Number of intervals on graphs')
    parser.add_argument('--save', '-s', action='store_false', help='Save graphs')
    args = parser.parse_args()

    pcap = pyshark.FileCapture(args.pcap_file_name, display_filter="tcp")
    num_intervals = args.num_intervals

    packet_storage = []

    max_stream = 0
    max_time = 0
    for packet in pcap:
        stream_num = int(packet.tcp.stream)
        if stream_num > max_stream:
            max_stream = stream_num
        if float(packet.tcp.time_relative) > max_time:
            max_time = float(packet.tcp.time_relative)
        try:
            packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet.tcp.time_relative))
        except IndexError:
            packet_storage.append([])
            while len(packet_storage) < stream_num + 1:
                packet_storage.append([])
            packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet.tcp.time_relative))

    time_unit = max_time / num_intervals
    plt.rcParams["figure.figsize"] = (9, math.ceil(max_stream / 3) * 3)

    for stream_packets in packet_storage:
        times = []
        lengths = []
        stream = stream_packets[0].stream
        current_time = 0
        while current_time < max_time:
            interval_length = 0
            for packet in stream_packets:
                if current_time < packet.time_relative < current_time + time_unit:
                    interval_length += packet.length
            times.append(current_time)
            lengths.append(interval_length)
            current_time += time_unit
        plt.subplot(max_stream // 3 + 1, 3, stream + 1)
        # plt.plot(times, lengths, '.')
        times.append(max_time)
        plt.stairs(lengths, times, fill=True)
        plt.title(stream)
        plt.xlabel('time')
        plt.ylabel('length')

    plt.tight_layout()

    now = datetime.now()
    now.replace(microsecond=0)
    plt.savefig('streams_graph_' + now.isoformat(sep='_', timespec='seconds') + '.png')
