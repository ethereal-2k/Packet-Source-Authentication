# GPU-Accelerated Packet Authentication: Sender & Receiver

This repository implements a CUDA-based simulation of secure packet transmission using parallel hashing. It includes a **Sender**, a **Receiver**, and a standalone **Packet Hashing** tool to compute hashes from `.pcap` files using the GPU.

---

## 🧩 Components

- **`sender.cu`**  
  Captures packets from a `.pcap` file or live interface, hashes each packet's header using CUDA, and transmits the modified packets (with embedded hashes) to the receiver.  
  Also records timing metrics for:
  - Flattening and GPU transfer
  - Kernel execution
  - Transmission and round-trip time

- **`receiver.cu`**  
  Receives packets over TCP, extracts headers and hashes, recomputes hashes using CUDA, and validates them against the received ones.  
  Also measures and logs timing for:
  - Reception
  - GPU computation
  - Hash verification

- **`hash_from_file.cu`**  
  A standalone tool that reads a `.pcap` file, hashes the packet headers in parallel on the GPU, and outputs the hashes.  
  You must edit the file to set the name of the `.pcap` file before compiling.

---

## ⚙️ Compilation Instructions

Requires **CUDA Toolkit** and **libpcap**.

### Compile Sender

```bash
nvcc sender.cu -o sender -lpcap
```

### Compile Receiver

```bash
nvcc receiver.cu -o receiver
```

### Compile Hashing Tool

Edit `hash_from_file.cu` to specify the name of the input `.pcap` file.

```bash
nvcc hash_from_file.cu -o hashpcap -lpcap
```

---

## 🚀 Running the Programs

### Start Receiver

```bash
./receiver
```

### Then Start Sender

```bash
./sender
```

### Optional: Run Hashing Tool

```bash
./hashpcap
```

---

## 🛠️ Dependencies

- CUDA Toolkit (`nvcc`)
- libpcap

Install dependencies (Ubuntu/Debian):

```bash
sudo apt-get install libpcap-dev
```

---

## 📁 File Structure

```
.
├── sender.cu           # Captures, hashes, and sends packets
├── receiver.cu         # Receives, rehashes, and validates packets
├── hash_from_file.cu   # Standalone packet hashing tool
├── README.md           # This file
```

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.
