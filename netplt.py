import argparse
import math
import pyshark
import matplotlib.pyplot as plt
from datetime import datetime
import os
import subprocess


class PacketInfo:
    def __init__(self, stream, length, time_relative):
        self.stream = int(stream)
        self.length = float(length)
        self.time_relative = float(time_relative)

    def __str__(self):
        return "% s % s % s" % (self.stream, self.length, self.time_relative)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build graphs for TCP steams')
    parser.add_argument('path', type=str, help='Path to pcap file or directory with pcap files')
    parser.add_argument('mode', nargs='?', type=str, default='grid', help='Graph type: grid or united plot')
    parser.add_argument('streams', nargs='?', type=str, default='all', help='Streams to be plotted, space-separated')
    parser.add_argument('time_unit', nargs='?', type=int, default=1, help='Time unit on the plot')
    args = parser.parse_args()

    time_unit = args.time_unit

    if os.path.isdir(args.path):
        for file in os.listdir(args.path):
            if os.path.splitext(file)[1] == ".pcap":
                subprocess.run(["python3", "netplt.py", args.path + file, args.mode, args.streams, str(time_unit)])
            elif not os.path.isdir(args.path + "/" + file):
                print(file + " is not .pcap file")

    elif os.path.isfile(args.path):

        pcap = pyshark.FileCapture(args.path, display_filter="tcp")

        selected_streams = []
        selected_streams_str = args.streams
        if selected_streams_str != 'all':
            selected_streams = sorted([int(x) for x in selected_streams_str.split()])

        packet_storage = {}

        max_stream = 0
        max_time = 0
        min_time = float(pcap[0].sniff_timestamp)
        for packet in pcap:
            if float(packet.sniff_timestamp) < min_time:
                min_time = packet.sniff_timestamp
        for packet in pcap:
            packet_time = float(packet.sniff_timestamp) - min_time
            stream_num = int(packet.tcp.stream)
            if stream_num > max_stream:
                max_stream = stream_num
            if packet_time > max_time:
                max_time = packet_time
            if selected_streams_str == 'all' or stream_num in selected_streams:
                try:
                    packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet_time))
                except KeyError:
                    packet_storage[stream_num] = []
                    packet_storage[stream_num].append(PacketInfo(stream_num, packet.tcp.len, packet_time))

        if args.mode == "grid":
            if len(packet_storage) == 1:
                plt.rcParams["figure.figsize"] = (3, 3)
            elif len(packet_storage) == 2:
                plt.rcParams["figure.figsize"] = (6, 3)
            elif selected_streams_str == 'all':
                plt.rcParams["figure.figsize"] = (9, math.ceil((max_stream + 1) / 3) * 3)
            else:
                plt.rcParams["figure.figsize"] = (9, math.ceil(len(selected_streams) / 3) * 3)

            pos = 1
            for stream, stream_packets in packet_storage.items():
                times = []
                lengths = []
                current_time = 0
                while current_time < max_time:
                    interval_length = 0
                    for packet in stream_packets:
                        if current_time < packet.time_relative < current_time + time_unit:
                            interval_length += packet.length
                    times.append(current_time)
                    lengths.append(interval_length)
                    current_time += time_unit
                if len(packet_storage) == 2:
                    plt.subplot(1, 2, pos)
                elif len(packet_storage) > 2:
                    if selected_streams_str == 'all':
                        plt.subplot(math.ceil((max_stream + 1) / 3), 3, stream + 1)
                    else:
                        plt.subplot(math.ceil(len(selected_streams) / 3), 3, pos)
                times.append(max_time)
                plt.stairs(lengths, times, fill=True)
                plt.title(stream)
                plt.xlabel('time')
                if time_unit == 1:
                    plt.ylabel('bits/sec')
                else:
                    plt.ylabel('bits/' + str(time_unit) + 'sec')
                pos += 1

            plt.tight_layout()

            now = datetime.now()
            now.replace(microsecond=0)
            x = args.path.split("/")
            plt.savefig('streams_graph_grid_' + x[len(x) - 1].split(".")[0] + '.png')

        elif args.mode == "united":
            plt.rcParams["figure.figsize"] = (6, 6)

            pos = 1
            for stream, stream_packets in packet_storage.items():
                times = []
                lengths = []
                current_time = 0
                while current_time < max_time:
                    interval_length = 0
                    for packet in stream_packets:
                        if current_time < packet.time_relative < current_time + time_unit:
                            interval_length += packet.length
                    times.append(current_time)
                    lengths.append(interval_length)
                    current_time += time_unit
                times.append(max_time)
                plt.stairs(lengths, times, fill=True, label=stream)
                pos += 1

            if (selected_streams_str == 'all' and max_stream < 22) or (0 < len(selected_streams) < 22):
                lgd = plt.legend(bbox_to_anchor=(1, 1), loc='upper left')
            else:
                lgd = plt.legend(ncol=math.ceil((max_stream + 1) / 21), bbox_to_anchor=(1, 1), loc='upper left')
            plt.xlabel('time')
            if time_unit == 1:
                plt.ylabel('bits/sec')
            else:
                plt.ylabel('bits/' + str(time_unit) + 'sec')
            now = datetime.now()
            now.replace(microsecond=0)
            x = args.path.split("/")
            plt.title(x[len(x) - 1].split(".")[0])

            plt.savefig('streams_graph_united_' + x[len(x) - 1].split(".")[0] + '.png', bbox_extra_artists=(lgd,),
                        bbox_inches='tight')

        else:
            print("Wrong input")

    else:
        print("Wrong input")
