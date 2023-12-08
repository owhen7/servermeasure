#Owen Wexler and Dylan Pourkay.

#import logging
import numpy as np
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 
import sys
import time
import math

def calculate_percentiles(response_times):
    sorted_data = sorted(response_times)

    n = len(sorted_data)
    p25_index = int(0.25 * n)
    p50_index = int(0.50 * n)
    p75_index = int(0.75 * n)
    p95_index = int(0.95 * n)
    p99_index = int(0.99 * n)

    p25 = sorted_data[p25_index]
    p50 = sorted_data[p50_index]
    p75 = sorted_data[p75_index]
    p95 = sorted_data[p95_index]
    p99 = sorted_data[p99_index]

    print(f"PERCENTILES: {p25:.5f} {p50:.5f} {p75:.5f} {p95:.5f} {p99:.5f}")
    


def with_numpy_calculate_percentiles(data):
    # Calculate percentiles using NumPy

    p25 = np.percentile(data, 25)
    p50 = np.percentile(data, 50)
    p75 = np.percentile(data, 75)
    p95 = np.percentile(data, 95)
    p99 = np.percentile(data, 99)

    #Print the result with at least 5 digits of accuracy to the left of the decimal point
    print(f"PERCENTILES: {p25:.5f} {p50:.5f} {p75:.5f} {p95:.5f} {p99:.5f}")


def processTheProcessedFile(sessions):

    http_requests = {}  # Dictionary to store HTTP requests temporarily. We empty this by the end.
    http_tuples = []    # List to store matched request and response tuples
    response_times = []  # List to store server response times
    number_of_packets_total = 0  
    number_of_tcp_packets = 0
    number_of_udp_packets = 0
    request_counter = 0
    response_counter = 0

    #Note: There is only one "session" per test case, so "sessions" just contains the one session.

    for session in sessions:                   
        for packet in sessions[session]:    # for each packet in each session
            number_of_packets_total = number_of_packets_total + 1  #increment total packet count 
            if packet.haslayer(TCP):        # check is the packet is a TCP packet

                number_of_tcp_packets = number_of_tcp_packets + 1   # count TCP packets 
                source_ip = packet[IP].src   # note that a packet is represented as a python hash table with keys corresponding to 
                dest_ip = packet[IP].dst     # layer field names and the values of the hash table as the packet field values
                
                if packet.haslayer(HTTP):
                    if HTTPRequest in packet:   
                        arrival_time = packet.time
                        request_info = (arrival_time, dest_ip, packet) # WE "REMEMBER" the arrival time and the TCP ports and IP addresses HERE.
                        request_id = (source_ip, dest_ip, packet[TCP].sport) # We use this to uniquely identify shit in the dictionary.
                        http_requests[request_id] = request_info
                        request_counter = request_counter + 1

                    elif HTTPResponse in packet:
                        response_counter = response_counter + 1
                        response_id = (dest_ip, source_ip, packet[TCP].dport) 

                        if response_id in http_requests:
                            response_info = (packet.time, source_ip, packet)
                            request_info = http_requests[response_id]

                            #time_difference = response_info[0] - request_info[0]
                            time_difference = float(response_info[0] - request_info[0])

                            response_times.append(time_difference)
                            http_tuples.append((http_requests[response_id], response_info))
                            del http_requests[response_id]  # remove matched request from the dictionary
            else:
                if packet.haslayer(UDP):
                    number_of_udp_packets = number_of_udp_packets + 1

        average_response_time = sum(response_times) / len(response_times)
        print(f"AVERAGE LATENCY: {average_response_time:.5f}")
        #This function prints out the percentiles.


        calculate_percentiles(response_times)
    #with_numpy_calculate_percentiles(response_times)


    #DEBUGGING SHIT. PRINT IF YOU WANT.
    # print("Got %d packets total, %d TCP packets and %d UDP packets" % (number_of_packets_total, number_of_tcp_packets,number_of_udp_packets))
    # print(request_counter)
    # print(response_counter)
    # print("Server Response Times:")
    # for idx, time_difference in enumerate(response_times, start=1):
    #     print(f"Response {idx}: {time_difference} seconds")
    #Print Average Latency.
    

def main():

    #python measure-webserver.py pcap1.pcap 93.184.216.34 80
    if len(sys.argv) != 4:
        print("USAGE: python3 measurewebserver.py [input-file] [server-ip] [server-port]")
        sys.exit(1)

    pcap_filename = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = sys.argv[3]

    # make sure to load the HTTP layer or your code wil silently fail
    load_layer("http")
    processed_file = rdpcap(pcap_filename)  # read in the pcap file 
    sessions = processed_file.sessions()    #  get the list of sessions 

    processTheProcessedFile(sessions)

if __name__ == "__main__":
    main()