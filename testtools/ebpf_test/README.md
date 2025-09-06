
# UPF eBPF Flow Analytics API Test Suite

This test suite provides comprehensive testing tools for UPF eBPF Flow Analytics APIs, allowing you to selectively test different API endpoints.

## 📁 File Structure

```
testtools/ebpf_test/
├── main.py          # Interactive main test script  
├── requirements.txt # Python dependencies
└── README.md        # Documentation
```

## 🚀 Quick Start

### Prerequisites
- Python 3.6+
- requests library: `pip install requests`
- UPF service running on `127.0.0.8:8888`

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run Tests

#### Interactive Testing (Recommended)
```bash
python main.py
```
Provides a complete interactive menu to test specific APIs.

## 📋 Available API Endpoints

### 🔍 Flow Analytics APIs
- **Flow Statistics (All)**: `GET /nwdaf-oam/flows/statistics`
- **Flow Statistics (Specific)**: `GET /nwdaf-oam/flows/statistics/{srcIP}/{dstIP}/{srcPort}/{dstPort}`
- **Packet Records (All)**: `GET /nwdaf-oam/flows/packet-records`
- **Packet Records (Specific)**: `GET /nwdaf-oam/flows/packet-records/{srcIP}/{dstIP}/{srcPort}/{dstPort}`
- **Flow Count**: `GET /nwdaf-oam/flows/count`
- **Packets Count (Combined)**: `GET /nwdaf-oam/packets-count`

### 📊 Source IP Analytics APIs
- **Source IPs (All)**: `GET /nwdaf-oam/source-ips`
- **Source IP (Specific)**: `GET /nwdaf-oam/source-ips/{ip}`
- **Source IPs Count**: `GET /nwdaf-oam/source-ips/count`
- **Top Source IPs**: `GET /nwdaf-oam/source-ips/top`
- **Source IPs Statistics**: `GET /nwdaf-oam/source-ips/stats`
- **Clear Source IPs**: `DELETE /nwdaf-oam/source-ips`

### 🎛️ Sampling Configuration APIs
- **Get Sampling Configuration**: `GET /nwdaf-oam/sampling-config`
- **Update Sampling Configuration (JSON)**: `PUT /nwdaf-oam/sampling-config`
- **Update Sampling Configuration (URL Param)**: `PUT /nwdaf-oam/sampling-config/{rate}`

### ⚙️ System APIs
- **Health Check**: `GET /nwdaf-oam/`
- **NF Resource**: `GET /nwdaf-oam/nf-resource`

## 🧪 Test Script Features

### main.py - Interactive Testing
- ✅ Complete menu system
- ✅ Individual API testing
- ✅ Specific flow parameter input
- ✅ Continuous monitoring mode
- ✅ Run all tests
- ✅ Formatted output with response time and content-type detection

## 📖 Usage Examples

### 1. Test Specific Flow Statistics
```bash
# Use main.py, select option 2
python main.py
> Select: 2. Flow Statistics (Specific Flow)
> Input: Source IP: 192.168.1.1
> Input: Destination IP: 192.168.1.100  
> Input: Source Port: 80
> Input: Destination Port: 8080
```

### 2. Continuous Monitoring Mode
```bash
# Use main.py, select option 15
python main.py
> Select: 15. Continuous Monitoring
> Choose API to monitor
> Set monitoring interval
```

### 4. Test Sampling Configuration
```bash
# Use main.py, select sampling configuration options
python main.py
> Select: 15. Get Sampling Configuration
> Select: 16. Update Sampling Configuration (JSON)
> Select: 17. Update Sampling Configuration (URL Param)
> Select: 18. Sampling Configuration Workflow Test
> Select: 19. Sampling Configuration Error Cases
```

### 5. Sampling Configuration Continuous Monitoring
```bash
# Use main.py, select option 20, then option 6
python main.py
> Select: 20. Continuous Monitoring
> Select: 6. Sampling Configuration
> Set monitoring interval
```

## 📊 Output Format

The test script provides structured output:

```
🧪 Flow Statistics (All Flows)
📡 URL: http://127.0.0.8:8000/nwdaf-oam/flows/statistics
📊 Status Code: 200
📋 Content-Type: application/json
📄 Response Body (JSON):
{
  "flows": [...]
}
⏱️  Response Time: 0.045s
✅ Test Passed
```

## 🐛 Troubleshooting

### Common Issues

1. **Connection Error**
   - Ensure UPF service is running on `127.0.0.8:8000`
   - Check firewall settings

2. **API 404 Error**
   - Verify UPF version supports all API endpoints
   - Check routing configuration

3. **Timeout Error**
   - Check network latency
   - Ensure UPF service is responsive

### Debug Mode
Enable verbose logging by setting environment variable:
```bash
export DEBUG=1
python main.py
```