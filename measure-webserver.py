#Owen Wexler and Dylan Pourkay.
import numpy as np
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP, IP

from scapy.all import *
import sys


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

    print(f"PERCENTILES: {p25} {p50} {p75} {p95} {p99}")

def processTheProcessedFile(sessions, server_ip, server_port):
    http_requests = {}
    response_times = []

    for session in sessions:
        for pkt in sessions[session]:
            if pkt.haslayer(HTTP):
                source_ip = pkt[IP].src
                dest_ip = pkt[IP].dst
                if HTTPRequest in pkt:
                    if str(pkt[IP].dst) == server_ip and str(pkt[TCP].dport) == server_port:
                        arrival_time = pkt.time
                        request_info = (arrival_time, dest_ip, pkt)
                        request_id = (source_ip, dest_ip, pkt[IP].sport)
                        http_requests[request_id] = request_info
                elif HTTPResponse in pkt:
                    response_id = (dest_ip, source_ip, pkt[IP].dport)
                    if response_id in http_requests and (str(pkt[IP].src) == server_ip and str(pkt[TCP].sport) == server_port):
                        response_info = (pkt.time, source_ip, pkt)
                        request_info = http_requests[response_id]
                        time_difference = float(response_info[0] - request_info[0])
                        response_times.append(time_difference)
                        del http_requests[response_id]
        average_response_time = sum(response_times) / len(response_times)
        print(f"AVERAGE LATENCY: {average_response_time}")
        calculate_percentiles(response_times)
        print(f"KL DIVERGENCE: {compute_kl_divergence(response_times)}")

def exponential_cdf(x, lambda_param):
    return 1 - np.exp(-lambda_param * x)

def compute_kl_divergence(latencies):
    num_buckets = 10
    max_latency = max(latencies)
    bucket_edges = np.linspace(0, max_latency, num_buckets + 1)
    bucket_edges[num_buckets] = float('inf')
    bucket_counts, _ = np.histogram(latencies, bins=bucket_edges)
    total_counts = sum(bucket_counts)
    measured_distribution = [count / total_counts for count in bucket_counts]

    mean_latency = np.mean(latencies)
    lambda_param = 1.0 / mean_latency

    modeled_distribution = []
    for i in range(num_buckets):
        lower_bound = bucket_edges[i]
        upper_bound = bucket_edges[i + 1] if i != num_buckets - 1 else float('inf')
        prob_mass = exponential_cdf(upper_bound, lambda_param) - exponential_cdf(lower_bound, lambda_param)
        modeled_distribution.append(prob_mass)
    kl_divergence = 0
    for p, q in zip(measured_distribution, modeled_distribution):
        if p > 0 and q > 0:
            kl_divergence += p * np.log2(p / q)
    return kl_divergence

def main():
    #python measure-webserver.py pcap1.pcap 93.184.216.34 80
    if len(sys.argv) != 4:
        print("USAGE: python3 measurewebserver.py [input-file] [server-ip] [server-port]")
        sys.exit(1)

    pcap_filename = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = sys.argv[3]

    load_layer("http")
    processed_file = rdpcap(pcap_filename)
    sessions = processed_file.sessions()

    processTheProcessedFile(sessions, server_ip, server_port)

if __name__ == "__main__":
    main()