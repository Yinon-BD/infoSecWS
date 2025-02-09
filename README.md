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

## 🚀 How It Works

### Intrusion Prevention System (IPS)
1. The IPS is implemented as an **HTTP proxy** that intercepts and inspects HTTP requests from **external networks**.
2. Each incoming request is scanned for **PHP serialized objects**.
3. If a PHP serialized object is detected, the request is **blocked**, preventing potential deserialization attacks.
4. Otherwise, the request is forwarded to its original destination.

### Data Leak Prevention (DLP)
1. The DLP system is a **proxy server** that inspects **outgoing HTTP and SMTP traffic** from the internal network.
2. Each outgoing data stream is processed and sent to a **pre-trained SVC model**.
3. The model analyzes the data and determines whether it contains a **C source file**.
4. If a C file is detected, the request is **blocked** to prevent a potential data leak.
5. Otherwise, the request is allowed to proceed to its destination.

## 📁 Project Structure (new relevant files detailed)

/HW5
│── /user
│   ├── IPS.py                            # HTTP Proxy for Intrusion Prevention
│   ├── DLP.py                            # HTTP & SMTP Proxy for Data Leak Prevention
│   ├── code_classifier_model.pkl         # Trained SVC model
│
|──/module - no changes...
|
|──/ftp - no changes...
|
|──/http - no changes...
|
└── README.md

