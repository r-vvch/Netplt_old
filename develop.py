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
    pcap_file_name = "/home/roman/My/YouTube_TCP/test.pcap"
    pcap = pyshark.FileCapture(pcap_file_name, display_filter="tcp")
    num_intervals = 10
    selected_streams = []
    selected_streams_str = '0 3 7 1 8'
    if selected_streams_str != 'all':
        selected_streams = sorted([int(x) for x in selected_streams_str.split()])

    packet_storage = []

    max_stream = 0
    max_time = 0
    for packet in pcap:
        stream_num = int(packet.tcp.stream)
        if stream_num > max_stream:
            max_stream = stream_num
        if float(packet.tcp.time_relative) > max_time:
            max_time = float(packet.tcp.time_relative)
        if selected_streams_str == 'all' or stream_num in selected_streams:
            try:
                packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet.tcp.time_relative))
            except IndexError:
                packet_storage.append([])
                while len(packet_storage) < stream_num + 1:
                    packet_storage.append([])
                packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet.tcp.time_relative))

    time_unit = max_time / num_intervals
    if selected_streams_str == 'all':
        plt.rcParams["figure.figsize"] = (9, math.ceil(max_stream / 3) * 3)
    else:
        plt.rcParams["figure.figsize"] = (9, math.ceil(len(selected_streams) / 3) * 3)

    pos = 1
    for stream_packets in packet_storage:
        if len(stream_packets) != 0:
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
            if selected_streams_str == 'all':
                plt.subplot(math.ceil(max_stream / 3), 3, stream + 1)
            else:
                plt.subplot(math.ceil(len(selected_streams) / 3), 3, pos)
            times.append(max_time)
            plt.stairs(lengths, times, fill=True)
            plt.title(stream)
            plt.xlabel('time')
            plt.ylabel('length')
            pos += 1

    plt.tight_layout()
    plt.show()
