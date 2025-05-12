#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <pcap.h>
#include <cuda_runtime.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

// #include "SHA256.h" // Uncomment if needed


#define byteSwap32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))
#define byteSwap64(x)                                                          \
    ((((x) >> 56) & 0x00000000000000FF) | (((x) >> 40) & 0x000000000000FF00) | \
     (((x) >> 24) & 0x0000000000FF0000) | (((x) >> 8) & 0x00000000FF000000) |  \
     (((x) << 8) & 0x000000FF00000000) | (((x) << 24) & 0x0000FF0000000000) |  \
     (((x) << 40) & 0x00FF000000000000) | (((x) << 56) & 0xFF00000000000000))

#define sig0(x) (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3))
#define sig1(x) (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10))

#define rotr(x, a) ((x >> a) | (x << (32 - a)))
#define shr(x, b) (x >> b)

#define SIG0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define SIG1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))

#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

union messageBlock
{
    __uint8_t e[64];
    __uint32_t t[16];
    __uint64_t s[8];
};

__device__ enum status
{
    READ,
    PAD0,
    PAD1,
    FINISH
};

__device__ static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    
__device__ uint16_t compute_checksum(const unsigned char *addr, int len)
{
    uint32_t sum = 0;

    // Process 16-bit words
    for (int i = 0; i < len - 1; i += 2)
    {
        uint16_t word = (addr[i] << 8) | addr[i + 1];
        sum += word;
    }

    // If there's an odd byte left
    if (len % 2 == 1)
    {
        uint16_t last_byte = addr[len - 1] << 8; // Big-endian padding
        sum += last_byte;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~((uint16_t)sum);
}


__device__ void calculateHashFromMemory(const unsigned char *data, size_t length, uint32_t output[8])
{
    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    // printf("Data Length = %zu\n", length);

    // **Compute the required padded length (multiple of 64 bytes)**
    size_t paddedLength = ((length + 63) / 64) * 64;
    // printf("Padded Length = %zu\n", paddedLength);

    // **Check if the padded length exceeds the buffer size**
    if (paddedLength > sizeof(unsigned char) * 128) {
        //perror("Data length exceeds static buffer size");
        return;
    }

    // **Allocate the buffer and zero it out**
    unsigned char padded[128] = {0};

    // **Copy the original data to the padded buffer**
    memcpy(padded, data, length);

    // **Print the padded data for debugging**
    // printf("Padded Data: ");
    // for (size_t i = 0; i < paddedLength; i++) {
        // printf("%02x", padded[i]);
    // }
    // printf("\n");

    memcpy(padded, data, length);
    padded[length] = 0x80;
    uint64_t bit_len = length * 8;
    
    for (int i = 0; i < 8; i++)
    {
        padded[paddedLength - 1 - i] = (bit_len >> (8 * i)) & 0xFF;
    }

    for (size_t index = 0; index < paddedLength; index += 64)
    {
        uint32_t W[64];
        
        // Unrolling loop for W[0..15] initialization
        for (int i = 0; i < 16; ++i)
        {
            W[i] = (padded[index + (i * 4)] << 24) | (padded[index + (i * 4 + 1)] << 16) |
                   (padded[index + (i * 4 + 2)] << 8) | (padded[index + (i * 4 + 3)]);
        }

        // W[16..63] initialization (precompute sig0, sig1)
        for (int i = 16; i < 64; ++i)
        {
            uint32_t s0 = sig0(W[i - 15]);
            uint32_t s1 = sig1(W[i - 2]);
            W[i] = s1 + W[i - 7] + s0 + W[i - 16];
        }

        uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

        for (int i = 0; i < 64; ++i)
        {
            uint32_t T1 = h + SIG1(e) + Ch(e, f, g) + K[i] + W[i];
            uint32_t T2 = SIG0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    // Copy final hash to output buffer
    memcpy(output, H, sizeof(H));
}

#define THREADS_PER_BLOCK 256
#define PACKETS_PER_THREAD 10
#define HASH_SIZE 8  // 256-bit hash (8 uint32_t)
struct IPv4Header {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

__global__ void expandAndHashKernel(
    const unsigned char *d_headers_20b,
    int num_packets,
    const uint32_t *d_payload_lengths,
    uint32_t *d_hashes,
    const unsigned char *key,
    unsigned char *d_modified_headers)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int start_idx = idx * PACKETS_PER_THREAD;

    if (start_idx >= num_packets) return;

    for (int i = 0; i < PACKETS_PER_THREAD; ++i)
    {
        int packet_idx = start_idx + i;
        if (packet_idx >= num_packets) return;

        const unsigned char *in = &d_headers_20b[packet_idx * 20];
        unsigned char expanded[56];       // Only real packet header
        unsigned char expanded_with_key[120]; // For hashing only (56 + 64)

        // Step 1: Copy original 20-byte IPv4 header
        for (int j = 0; j < 20; ++j)
            expanded[j] = in[j];

        // Step 2: Set Version=4 and IHL=14 (56 bytes)
        expanded[0] = (4 << 4) | 0xE; // 0x4E

        // Step 3: Zero checksum
        expanded[10] = 0;
        expanded[11] = 0;

        // Step 4: Insert IP options
        expanded[20] = 0x82;  // Option type
        expanded[21] = 34;    // Option length

        for (int j = 0; j < 32; ++j)
            expanded[22 + j] = 0x00; // Placeholder for hash

        // Step 5: Insert 2-byte padding
        expanded[54] = 0x00;
        expanded[55] = 0x00;

        // Step 6: Prepare buffer for hashing
        for (int j = 0; j < 56; ++j)
            expanded_with_key[j] = expanded[j];

        for (int j = 0; j < 64; ++j)
            expanded_with_key[56 + j] = key[j];

        // Step 7: Hash over 120 bytes (header + key)
        uint32_t local_hash[HASH_SIZE];
        calculateHashFromMemory(expanded_with_key, 120, local_hash);

        /*if (packet_idx == 443) {
            for (int k = 0; k < 8; ++k)
                printf("HASH[%d] = %08x\n", k, local_hash[k]);
        }*/

        // Step 8: Insert hash into expanded header options
        for (int i = 0; i < 8; ++i) {
            expanded[22 + i * 4 + 0] = (local_hash[i] >> 24) & 0xFF;
            expanded[22 + i * 4 + 1] = (local_hash[i] >> 16) & 0xFF;
            expanded[22 + i * 4 + 2] = (local_hash[i] >> 8) & 0xFF;
            expanded[22 + i * 4 + 3] = (local_hash[i]) & 0xFF;
        }

        // Step 9: Recompute checksum over real 56-byte IPv4 header
        uint16_t csum = compute_checksum(expanded, 56);
        expanded[10] = (csum >> 8) & 0xFF;
        expanded[11] = csum & 0xFF;

        // Step 10: Store hash output separately
        for (int j = 0; j < HASH_SIZE; ++j)
            d_hashes[packet_idx * HASH_SIZE + j] = local_hash[j];

        // Step 11: Write only 56 bytes of expanded header to output
        unsigned char *out = &d_modified_headers[packet_idx * 56];
        for (int j = 0; j < 56; ++j)
            out[j] = expanded[j];
    }
}



const char *HMAC_KEY = "thisisaverysecure64bytehmacauthenticationkey12345678901234567890";
#define MAX_PACKETS 10000000
std::vector<std::vector<unsigned char>> eth_headers;
std::vector<std::vector<unsigned char>> ip_headers;
std::vector<std::vector<unsigned char>> payloads;
std::vector<uint32_t> payload_lengths;
int packet_count = 0;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    if (packet_count >= MAX_PACKETS) {
        pcap_breakloop((pcap_t*)user);
        return;
    }

    if (header->caplen < 14 + 20) return;

    const struct ether_header* eth = (struct ether_header*) packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const struct ip* ip_hdr = (struct ip*)(packet + 14);
    size_t ip_len = ip_hdr->ip_hl * 4;
    size_t payload_offset = 14 + ip_len;
    size_t payload_len = header->caplen > payload_offset ? header->caplen - payload_offset : 0;

    std::vector<unsigned char> ip_copy((unsigned char*)(packet + 14), (unsigned char*)(packet + 14 + ip_len));
    uint16_t orig_len = ntohs(*(uint16_t*)&ip_copy[2]);
    uint16_t new_len = htons(orig_len + 36);
    memcpy(&ip_copy[2], &new_len, sizeof(uint16_t));

    eth_headers.emplace_back(packet, packet + 14);
    ip_headers.emplace_back(std::move(ip_copy));
    payloads.emplace_back(packet + payload_offset, packet + payload_offset + payload_len);
    payload_lengths.push_back(payload_len);

    packet_count++;
    /*if (packet_count % 1000 == 0)
        std::cout << "Captured " << packet_count << " packets...\n";*/
}

int main() {
    using namespace std::chrono;

    const char* iface = "wlan0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_create(iface, errbuf);
    pcap_set_snaplen(handle, 65535);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1);
    pcap_set_buffer_size(handle, 64 * 1024 * 1024);
    if (pcap_activate(handle) < 0) {
        std::cerr << "[Sender] pcap_activate failed: " << pcap_geterr(handle) << "\n";
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[Sender] BPF filter setup failed.\n";
    }

    std::cout << "[Sender] Starting capture using pcap_loop...\n";
    auto t_capture_start = high_resolution_clock::now();
    int packet_limit = 10000000;
    pcap_loop(handle, packet_limit, packet_handler, (u_char*)handle);
    auto t_capture_end = high_resolution_clock::now();
    pcap_close(handle);

    std::cout << "[Sender] Captured total: " << packet_count << " packets\n";

    if (packet_count == 0) {
        std::cerr << "[Sender] No packets captured. Exiting.\n";
        return 0;
    }

    auto t_flatten_start = high_resolution_clock::now();
    std::vector<unsigned char> flat_headers(packet_count * 20);
    for (int i = 0; i < packet_count; ++i)
        memcpy(flat_headers.data() + i * 20, ip_headers[i].data(), 20);
    auto t_flatten_end = high_resolution_clock::now();

    unsigned char *d_headers_20b, *d_modified_headers;
    uint32_t *d_hashes, *d_payload_lengths;
    unsigned char *d_key;

    cudaMalloc(&d_headers_20b, packet_count * 20);
    cudaMalloc(&d_modified_headers, packet_count * 56);
    cudaMalloc(&d_hashes, packet_count * HASH_SIZE * sizeof(uint32_t));
    cudaMalloc(&d_payload_lengths, packet_count * sizeof(uint32_t));
    cudaMalloc(&d_key, 64);

    auto t_memcpy1_start = high_resolution_clock::now();
    cudaMemcpy(d_headers_20b, flat_headers.data(), flat_headers.size(), cudaMemcpyHostToDevice);
    cudaMemcpy(d_payload_lengths, payload_lengths.data(), packet_count * sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_key, HMAC_KEY, 64, cudaMemcpyHostToDevice);
    auto t_memcpy1_end = high_resolution_clock::now();

    int threadsPerBlock = 256;
    int totalThreads = (packet_count + PACKETS_PER_THREAD - 1) / PACKETS_PER_THREAD;
    int numBlocks = (totalThreads + threadsPerBlock - 1) / threadsPerBlock;

    auto t_kernel_start = high_resolution_clock::now();
    expandAndHashKernel<<<numBlocks, threadsPerBlock>>>(
        d_headers_20b, packet_count, d_payload_lengths, d_hashes, d_key, d_modified_headers);
    cudaDeviceSynchronize();
    auto t_kernel_end = high_resolution_clock::now();

    std::vector<unsigned char> flat_modified_headers(packet_count * 56);
    auto t_memcpy2_start = high_resolution_clock::now();
    cudaMemcpy(flat_modified_headers.data(), d_modified_headers, flat_modified_headers.size(), cudaMemcpyDeviceToHost);
    auto t_memcpy2_end = high_resolution_clock::now();

    auto t_reconstruct_start = high_resolution_clock::now();
    std::vector<std::vector<unsigned char>> modified_packets;
    for (int i = 0; i < packet_count; ++i) {
        std::vector<unsigned char> pkt;
        pkt.insert(pkt.end(), eth_headers[i].begin(), eth_headers[i].end());
        pkt.insert(pkt.end(), flat_modified_headers.begin() + i * 56, flat_modified_headers.begin() + (i + 1) * 56);
        pkt.insert(pkt.end(), payloads[i].begin(), payloads[i].end());
        modified_packets.push_back(std::move(pkt));
    }
    auto t_reconstruct_end = high_resolution_clock::now();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(9090);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    std::cout << "[Sender] Connecting to receiver...\n";
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("[Sender] connect");
        return 1;
    }

    auto t_rtt_start = high_resolution_clock::now();
    auto t_send_start = high_resolution_clock::now();
    for (const auto& pkt : modified_packets) {
        uint32_t pkt_size = pkt.size();
        if (send(sockfd, &pkt_size, sizeof(pkt_size), 0) != sizeof(pkt_size)) {
            perror("[Sender] send(pkt_size)");
        }
        if (send(sockfd, pkt.data(), pkt.size(), 0) != (ssize_t)pkt.size()) {
            perror("[Sender] send(pkt)");
        }
    }
    auto t_send_end = high_resolution_clock::now();
    shutdown(sockfd, SHUT_WR);

    std::cout << "[Sender] Waiting for match results...\n";
    uint32_t received_count = 0;
    ssize_t r1 = recv(sockfd, &received_count, sizeof(received_count), MSG_WAITALL);
    if (r1 != sizeof(received_count)) {
        perror("[Sender] recv(count)");
    } else {
        std::vector<uint8_t> match_bytes(received_count);
        ssize_t r2 = recv(sockfd, match_bytes.data(), received_count, MSG_WAITALL);
        if (r2 != received_count) {
            perror("[Sender] recv(match_bytes)");
        } else {
            std::cout << "[Sender] Received match result array of size " << received_count << "\n";
        }
    }
    auto t_rtt_end = high_resolution_clock::now();

    close(sockfd);

    cudaFree(d_headers_20b);
    cudaFree(d_modified_headers);
    cudaFree(d_hashes);
    cudaFree(d_payload_lengths);
    cudaFree(d_key);

    auto ms = [](auto start, auto end) {
        return duration_cast<milliseconds>(end - start).count();
    };

    auto ns = [](auto start, auto end) {
        return duration_cast<nanoseconds>(end - start).count();
    };

    std::cout << "\n--- Timing Report ---\n";
    std::cout << "Packet capture         : " << ms(t_capture_start, t_capture_end) << " ms\n";
    std::cout << "Flatten headers        : " << ns(t_flatten_start, t_flatten_end) << " ns\n";
    std::cout << "Memcpy to device       : " << ns(t_memcpy1_start, t_memcpy1_end) << " ns\n";
    std::cout << "Kernel execution       : " << ns(t_kernel_start, t_kernel_end) << " ns\n";
    std::cout << "Memcpy from device     : " << ns(t_memcpy2_start, t_memcpy2_end) << " ns\n";
    std::cout << "Packet reconstruction  : " << ms(t_reconstruct_start, t_reconstruct_end) << " ms\n";
    std::cout << "Packet transmission    : " << ms(t_send_start, t_send_end) << " ms\n";
    std::cout << "Round-trip time        : " << ms(t_rtt_start, t_rtt_end) << " ms\n";

    if (packet_count > 0) {
        std::cout << "\n--- Avg Per-Packet Timing (nanoseconds) ---\n";
        std::cout << "Capture time           : " << (1.0 * ms(t_capture_start, t_capture_end) * 1000000 / packet_count) << " ns/packet\n";
        std::cout << "Flatten headers        : " << ns(t_flatten_start, t_flatten_end) / packet_count << " ns/packet\n";
        std::cout << "Memcpy to device       : " << ns(t_memcpy1_start, t_memcpy1_end) / packet_count << " ns/packet\n";
        std::cout << "Kernel execution       : " << ns(t_kernel_start, t_kernel_end) / packet_count << " ns/packet\n";
        std::cout << "Memcpy from device     : " << ns(t_memcpy2_start, t_memcpy2_end) / packet_count << " ns/packet\n";
        std::cout << "Packet reconstruction  : " << duration_cast<nanoseconds>(t_reconstruct_end - t_reconstruct_start).count() / packet_count << " ns/packet\n";
        std::cout << "Packet transmission    : " << duration_cast<nanoseconds>(t_send_end - t_send_start).count() / packet_count << " ns/packet\n";
        std::cout << "Round-trip total       : " << duration_cast<nanoseconds>(t_rtt_end - t_rtt_start).count() / packet_count << " ns/packet\n";
    }

    return 0;
}


