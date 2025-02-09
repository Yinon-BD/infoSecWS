# InfoSecWS HW5 - IPS & DLP

This repository contains the final part of the Firewall project, which includes an **Intrusion Prevention System (IPS)** and a **Data Leak Prevention (DLP)** system.

## 📌 Overview

The project enhances network security by implementing two key components:

1. **Intrusion Prevention System (IPS)**  
   - An HTTP proxy server that inspects incoming packets from external networks.
   - Detects and blocks any traffic containing **PHP serialized objects** to mitigate potential deserialization attacks.
   - Was designed to deal with the `GiveWP Unauthenticated Donation Process Exploit`

2. **Data Leak Prevention (DLP)**  
   - A proxy server for **HTTP and SMTP** traffic.
   - Analyzes outgoing traffic from the internal network to prevent **C source files** from being sent externally.
   - Uses a **trained SVC (Support Vector Classification) model** to classify data leaks.
   - The model inspects each outgoing data stream and decides whether it contains a C file.

## 🔧 Setup & Installation

To use the DLP system, ensure that the following dependencies are installed with the exact versions:

```bash
pip install scikit-learn==0.21.1.post numpy==1.16 scipy==1.2.3 joblib==0.14.1 threadpoolctl==2.0.0

```

