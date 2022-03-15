import os
import swpag_client
import socket
import struct
from pwn import *
import time

def filter_packet(in_packet):
   ip_header = in_packet[0:20]
   iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
   iph_length = (iph[0] & 0xF) * 4
   protocol = iph[6]
   if protocol == 6:
       tcp_header = in_packet[iph_length:iph_length + 20]
       tcph = struct.unpack('!HHLLBBHHH', tcp_header)
       dest_port = int(tcph[1])
       # packet has been ID'd as a potential attack so save data and process packet data
       if dest_port == 10004:
           sequence = tcph[2]
           acknowledgement = tcph[3]
           off_flags = tcph[4]
           tcph_length = off_flags >> 4
           flag_syn = (off_flags & 2) >> 1
           flag_fin = off_flags & 1
           h_size = iph_length + tcph_length * 4
           data_size = len(in_packet) - h_size  # has to be 0 for handshake
           # get data from the packet
           data = in_packet[h_size:]
           return dest_port, sequence, acknowledgement, flag_syn, flag_fin, data_size, data
   return -1

def save_tcp_packet(round_path, secs_passed, sequence, data):
   file_name = "secs{}_seq{}".format(secs_passed, sequence)
   file_path = os.path.join(round_path, file_name)
   with open(file_path, "wb") as file:  # include decoding? binary for speed
       file.write(data)

def run(args):  # arguments are team interface and token
   base_output_directory = 'Sniffer_Output/'
   # Try to collect attacks on port 10004 to aid in developing the same attack on other teams
   vulnerable_port = 10004
   # initiate client and socket. socket only collects incoming tcp packets coming through interface
   t22_client = swpag_client.Team(args.game_interface, args.team_token)
   t22_id = t22_client.get_vm()['team_id']
   t22_hostname = 'team22'
   s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

   # loops at the pace of once per round
   while True:
       current_round = int(t22_client.get_tick_info()['tick_id'])
       # a dictionary of vulnerable for a round ports and paths to save files

       round_path = os.path.join(base_output_directory, "round{}/".format(current_round))
       if not os.path.isdir(round_path):
           os.makedirs(round_path)

       t22_target_index = next((index for (index, d) in enumerate(t22_client.get_targets(4)) if d["hostname"] == t22_hostname), -1)

       # if there are no vulnerable services for this round sleep until end of round
       if t22_target_index == -1:
           print('No vulnerable services for Team 22 in Round {}'.format(current_round))
           sleeptime = int(t22_client.get_game_status()['tick']['approximate_seconds_left'])
           time.sleep(sleeptime)
           continue

       vuln_service_path = os.path.join(round_path, "port{}/".format(vulnerable_port))
       if not os.path.isdir(vuln_service_path):
           os.mkdir(vuln_service_path)

       # loops continuously while in current round collect raw incoming tcp packets over interface
       while int(t22_client.get_tick_info()['tick_id']) < current_round + 1:
           attack_score = t22_client.get_game_status()['scores'][t22_id]['attack_points']
           raw_packet = s.recvfrom(65535)
           pkt_to_be_filtered = filter_packet(raw_packet[0])
           # if packet is not tcp or is not a request to the vulnerable service / port then discard
           if pkt_to_be_filtered == -1:
               continue
           else:
               destination_port, sequence, acknowledgement, flag_syn, flag_fin, data_size, data = pkt_to_be_filtered
               # discard packet if below conditions are met, do because there is no data in packet
               if flag_syn == 1 or flag_fin == 1 or data_size == 0:
                   continue
               # pkt meets all conditions so save its data to its appropriate file
               else:
                   secs_left = str(int(t22_client.get_tick_info()["approximate_seconds_left"]))
                   save_tcp_packet(vuln_service_path, secs_left, sequence, data)

#note this will not run, presented for simplicity purposes
run(interface, token)
