#include <arpa/inet.h>
#include <chrono>
#include <cuda_runtime.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using namespace std::chrono;

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
    unsigned char *d_modified_headers,
    const uint32_t *d_extracted_hashes,
    uint8_t *d_match_flags)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int start_idx = idx * PACKETS_PER_THREAD;

    if (start_idx >= num_packets) return;

    for (int i = 0; i < PACKETS_PER_THREAD; ++i)
    {
        int packet_idx = start_idx + i;
        if (packet_idx >= num_packets) return;

        const unsigned char *in = &d_headers_20b[packet_idx * 20];
        unsigned char expanded[56];             // Modified IPv4 header
        unsigned char expanded_with_key[120];   // Input for hashing (header + key)

        // Step 1: Copy original 20-byte IPv4 header
        for (int j = 0; j < 20; ++j)
            expanded[j] = in[j];

        // Step 2: Set Version=4 and IHL=14 (56 bytes)
        expanded[0] = (4 << 4) | 0xE;

        // Step 3: Zero checksum
        expanded[10] = 0;
        expanded[11] = 0;

        // Step 4: Insert IP options (Option type = 0x82, length = 34)
        expanded[20] = 0x82;
        expanded[21] = 34;
        for (int j = 0; j < 32; ++j)
            expanded[22 + j] = 0x00;

        // Step 5: 2-byte padding
        expanded[54] = 0x00;
        expanded[55] = 0x00;

        // Step 6: Prepare 120-byte buffer for hashing
        for (int j = 0; j < 56; ++j)
            expanded_with_key[j] = expanded[j];
        for (int j = 0; j < 64; ++j)
            expanded_with_key[56 + j] = key[j];

        // Step 7: Hash the 120 bytes
        uint32_t local_hash[HASH_SIZE];
        calculateHashFromMemory(expanded_with_key, 120, local_hash);

        // Step 8: Insert hash into header options
        for (int j = 0; j < 8; ++j) {
            expanded[22 + j * 4 + 0] = (local_hash[j] >> 24) & 0xFF;
            expanded[22 + j * 4 + 1] = (local_hash[j] >> 16) & 0xFF;
            expanded[22 + j * 4 + 2] = (local_hash[j] >> 8)  & 0xFF;
            expanded[22 + j * 4 + 3] =  local_hash[j]        & 0xFF;
        }

        // Step 9: Recompute checksum on 56-byte header
        uint16_t csum = compute_checksum(expanded, 56);
        expanded[10] = (csum >> 8) & 0xFF;
        expanded[11] = csum & 0xFF;

        // Step 10: Store hash in global memory
        for (int j = 0; j < HASH_SIZE; ++j)
            d_hashes[packet_idx * HASH_SIZE + j] = local_hash[j];

        // Step 11: Write modified header to output
        unsigned char *out = &d_modified_headers[packet_idx * 56];
        for (int j = 0; j < 56; ++j)
            out[j] = expanded[j];

        // Step 12: Compare against extracted hash
        bool match = true;
        for (int j = 0; j < HASH_SIZE; ++j) {
            if (local_hash[j] != d_extracted_hashes[packet_idx * HASH_SIZE + j]) {
                match = false;
                break;
            }
        }
        d_match_flags[packet_idx] = match ? 1 : 0;
    }
}

const char *HMAC_KEY = "thisisaverysecure64bytehmacauthenticationkey12345678901234567890";

int main() {
    const int PORT = 9090;
    int server_fd, client_fd;
    struct sockaddr_in address{};
    int addrlen = sizeof(address);

    auto t_recv_start = high_resolution_clock::now();

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    std::cout << "[Receiver] Listening on port " << PORT << "...\n";

    client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (client_fd < 0) {
        perror("accept");
        close(server_fd);
        return 1;
    }

    std::cout << "[Receiver] Connection accepted.\n";

    std::vector<std::vector<unsigned char>> ip_headers;
    std::vector<uint32_t> payload_lengths;
    std::vector<uint32_t> extracted_hashes;
    int packet_count = 0;

    while (true) {
        uint32_t pkt_size;
        ssize_t len = recv(client_fd, &pkt_size, sizeof(pkt_size), MSG_WAITALL);
        if (len <= 0) break;

        std::vector<unsigned char> packet(pkt_size);
        ssize_t received = recv(client_fd, packet.data(), pkt_size, MSG_WAITALL);
        if (received <= 0) break;

        if (pkt_size < 14 + 56) continue;

        const unsigned char* ip_start = packet.data() + 14;
        ip_headers.emplace_back(ip_start, ip_start + 56);
        payload_lengths.push_back(pkt_size - (14 + 56));

        for (int i = 0; i < HASH_SIZE; ++i) {
            uint32_t h;
            memcpy(&h, ip_start + 22 + i * 4, sizeof(uint32_t));
            h = ntohl(h);
            extracted_hashes.push_back(h);
        }

        packet_count++;
    }

    auto t_recv_end = high_resolution_clock::now();
    if (packet_count == 0) {
        std::cerr << "[Receiver] No packets received. Exiting.\n";
        close(client_fd);
        close(server_fd);
        return 0;
    }

    std::cout << "[Receiver] Captured " << packet_count << " packets\n";

    auto t_flatten_start = high_resolution_clock::now();
    std::vector<unsigned char> flat_headers(packet_count * 20);
    for (int i = 0; i < packet_count; ++i)
        memcpy(flat_headers.data() + i * 20, ip_headers[i].data(), 20);
    auto t_flatten_end = high_resolution_clock::now();

    unsigned char *d_headers_20b, *d_modified_headers, *d_key;
    uint32_t *d_hashes, *d_payload_lengths, *d_extracted_hashes;
    uint8_t *d_match_flags;

    auto t_memcpy1_start = high_resolution_clock::now();
    cudaMalloc(&d_headers_20b, packet_count * 20);
    cudaMalloc(&d_modified_headers, packet_count * 56);
    cudaMalloc(&d_hashes, packet_count * HASH_SIZE * sizeof(uint32_t));
    cudaMalloc(&d_payload_lengths, packet_count * sizeof(uint32_t));
    cudaMalloc(&d_key, 64);
    cudaMalloc(&d_extracted_hashes, packet_count * HASH_SIZE * sizeof(uint32_t));
    cudaMalloc(&d_match_flags, packet_count * sizeof(uint8_t));

    cudaMemcpy(d_headers_20b, flat_headers.data(), flat_headers.size(), cudaMemcpyHostToDevice);
    cudaMemcpy(d_payload_lengths, payload_lengths.data(), packet_count * sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_key, HMAC_KEY, 64, cudaMemcpyHostToDevice);
    cudaMemcpy(d_extracted_hashes, extracted_hashes.data(), packet_count * HASH_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice);
    auto t_memcpy1_end = high_resolution_clock::now();

    int threadsPerBlock = 256;
    int totalThreads = (packet_count + PACKETS_PER_THREAD - 1) / PACKETS_PER_THREAD;
    int numBlocks = (totalThreads + threadsPerBlock - 1) / threadsPerBlock;

    auto t_kernel_start = high_resolution_clock::now();
    expandAndHashKernel<<<numBlocks, threadsPerBlock>>>(
        d_headers_20b, packet_count, d_payload_lengths,
        d_hashes, d_key, d_modified_headers,
        d_extracted_hashes, d_match_flags);
    cudaDeviceSynchronize();
    auto t_kernel_end = high_resolution_clock::now();

    auto t_memcpy2_start = high_resolution_clock::now();
    std::vector<uint8_t> match_bytes(packet_count);
    cudaMemcpy(match_bytes.data(), d_match_flags, packet_count * sizeof(uint8_t), cudaMemcpyDeviceToHost);
    auto t_memcpy2_end = high_resolution_clock::now();

    auto t_send_start = high_resolution_clock::now();
    ssize_t sent1 = send(client_fd, &packet_count, sizeof(packet_count), 0);
    if (sent1 != sizeof(packet_count)) {
        perror("[Receiver] Failed to send count");
    }

    ssize_t sent2 = send(client_fd, match_bytes.data(), match_bytes.size(), 0);
    if (sent2 != (ssize_t)match_bytes.size()) {
        perror("[Receiver] Failed to send match results");
    }
    auto t_send_end = high_resolution_clock::now();

    std::cout << "[Receiver] Done sending match results.\n";

    // Cleanup
    close(client_fd);
    close(server_fd);
    cudaFree(d_headers_20b);
    cudaFree(d_modified_headers);
    cudaFree(d_hashes);
    cudaFree(d_payload_lengths);
    cudaFree(d_key);
    cudaFree(d_extracted_hashes);
    cudaFree(d_match_flags);

    auto ms = [](auto start, auto end) {
        return duration_cast<milliseconds>(end - start).count();
    };

    auto ns = [](auto start, auto end) {
        return duration_cast<nanoseconds>(end - start).count();
    };

    std::cout << "\n--- Timing Report ---\n";
    std::cout << "Packet reception       : " << ms(t_recv_start, t_recv_end) << " ms\n";
    std::cout << "Flatten headers        : " << ns(t_flatten_start, t_flatten_end) << " ns\n";
    std::cout << "Memcpy to device       : " << ns(t_memcpy1_start, t_memcpy1_end) << " ns\n";
    std::cout << "Kernel execution       : " << ns(t_kernel_start, t_kernel_end) << " ns\n";
    std::cout << "Memcpy from device     : " << ns(t_memcpy2_start, t_memcpy2_end) << " ns\n";
    std::cout << "Match result send      : " << ns(t_send_start, t_send_end) << " ns\n";

    if (packet_count > 0) {
        std::cout << "\n--- Avg Per-Packet Timing (nanoseconds) ---\n";
        std::cout << "Reception time         : " << (1.0 * ms(t_recv_start, t_recv_end) * 1e6 / packet_count) << " ns/packet\n";
        std::cout << "Flatten headers        : " << ns(t_flatten_start, t_flatten_end) / packet_count << " ns/packet\n";
        std::cout << "Memcpy to device       : " << ns(t_memcpy1_start, t_memcpy1_end) / packet_count << " ns/packet\n";
        std::cout << "Kernel execution       : " << ns(t_kernel_start, t_kernel_end) / packet_count << " ns/packet\n";
        std::cout << "Memcpy from device     : " << ns(t_memcpy2_start, t_memcpy2_end) / packet_count << " ns/packet\n";
        std::cout << "Result send            : " << ns(t_send_start, t_send_end) / packet_count << " ns/packet\n";
    }

    return 0;
}






