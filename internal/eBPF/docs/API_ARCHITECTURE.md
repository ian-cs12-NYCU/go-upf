# UPF eBPF Flow Analytics API Architecture

This document describes the refactored UPF eBPF flow analytics API architecture.

```
[GIN-debug] GET    /nwdaf-oam/               --> github.com/free5gc/go-upf/internal/sbi.(*Server).getNwdafOamRoutes.func1 (3 handlers)
[GIN-debug] GET    /nwdaf-oam/nf-resource    --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamNfResourceGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/statistics --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamFlowStatisticsGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/statistics/:srcIP/:dstIP/:srcPort/:dstPort --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamFlowStatisticsByKeyGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/packet-records --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamPacketRecordsGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/packet-records/:srcIP/:dstIP/:srcPort/:dstPort --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamPacketRecordsByKeyGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/count    --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamFlowCountGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips     --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPsGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips/:ip --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPByIPGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips/count --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPsCountGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips/top --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamTopSourceIPsGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips/stats --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPsStatsGet-fm (3 handlers)
[GIN-debug] DELETE /nwdaf-oam/source-ips     --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPsClear-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/sampling-config --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSamplingConfigGet-fm (3 handlers)
[GIN-debug] PUT    /nwdaf-oam/sampling-config --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSamplingConfigUpdate-fm (3 handlers)
[GIN-debug] PUT    /nwdaf-oam/sampling-config/:rate --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSamplingConfigUpdateByParam-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/defaultK       --> github.com/free5gc/go-upf/internal/sbi.(*Server).HandleGetGlobalDefaultK-fm (3 handlers)
[GIN-debug] PUT    /nwdaf-oam/defaultK       --> github.com/free5gc/go-upf/internal/sbi.(*Server).HandleSetGlobalDefaultK-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/perf-buffer-config --> github.com/free5gc/go-upf/internal/sbi.(*Server).HandleGetPerfBufferConfig-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/perf-buffer-stats --> github.com/free5gc/go-upf/internal/sbi.(*Server).HandleGetPerfBufferStats-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/perf-buffer-lost-samples --> github.com/free5gc/go-upf/internal/sbi.(*Server).HandleGetPerfBufferLostSamples-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/:srcIP/:srcPort/:dstIP/:dstPort/:protocol/k --> github.com/free5gc/go-upf/internal/sbi.(*Server).HandleGetFlowK-fm (3 handlers)
[GIN-debug] PUT    /nwdaf-oam/flows/:srcIP/:srcPort/:dstIP/:dstPort/:protocol/k --> github.com/free5gc/go-upf/internal/sbi.(*Server).HandleSetFlowK-fm (3 handlers)
```

## Architecture Overview

### Previous Architecture
- Single `GetFlows` API handling all functionality

## Core eBPF APIs

### 1. Flow Statistics API
**GET** `/nwdaf-oam/flows/statistics`  
**GET** `/nwdaf-oam/flows/statistics/{srcIP}/{dstIP}/{srcPort}/{dstPort}`

Retrieve basic flow statistics without packet records for lightweight monitoring. Returns source/destination IP and ports, packet count, bytes transferred, and first/last packet timestamps.

### 2. Packet Records API
**GET** `/nwdaf-oam/flows/packet-records`  
**GET** `/nwdaf-oam/flows/packet-records/{srcIP}/{dstIP}/{srcPort}/{dstPort}`

Extract detailed packet records from ring buffer for deep packet inspection. Returns recent packet details including length, protocol, direction (as human-readable strings: "Uplink"/"Downlink"/"Unknown"), TCP flags, and DSCP/ECN values.

### 3. Flow Count API
**GET** `/nwdaf-oam/flows/count`

Provide total number of tracked flows for resource monitoring and system health checks.

## HTTP REST API Endpoints

### Flow Statistics Endpoints
- `GET /nwdaf-oam/flows/statistics` - Retrieve all flow statistics
- `GET /nwdaf-oam/flows/statistics/{srcIP}/{dstIP}/{srcPort}/{dstPort}` - Retrieve specific flow statistics

### Packet Records Endpoints
- `GET /nwdaf-oam/flows/packet-records` - Retrieve packet records for all flows
- `GET /nwdaf-oam/flows/packet-records/{srcIP}/{dstIP}/{srcPort}/{dstPort}` - Retrieve packet records for specific flow

### Utility Endpoints
- `GET /nwdaf-oam/flows/count` - Get total flow count

## API Usage Examples

### 1. Get All Flow Statistics
```bash
curl http://localhost:8080/nwdaf-oam/flows/statistics
```
**Purpose**: Quick overview of all active flows  
**Status Code**: 200  
**Content-Type**: application/json; charset=utf-8  
**Response Example**:
```json
{
  "count": 2,
  "flowStatistics": [
    {
      "srcIP": "10.60.0.1",
      "dstIP": "1.1.1.1",
      "srcPort": 2048,
      "dstPort": 0,
      "protocol": 17,
      "cnt": 4,
      "bytes": 568,
      "firstTime": {
        "ns": 1584931831473940,
        "formatted": "2025-09-25T08:15:31.831Z"
      },
      "lastTime": {
        "ns": 1584934840816072,
        "formatted": "2025-09-25T08:15:34.84Z"
      },
      "direction": "Uplink"
    },
    {
      "srcIP": "1.1.1.1",
      "dstIP": "10.60.0.1",
      "srcPort": 0,
      "dstPort": 0,
      "protocol": 17,
      "cnt": 4,
      "bytes": 336,
      "firstTime": {
        "ns": 1584931836195449,
        "formatted": "2025-09-25T08:15:31.836Z"
      },
      "lastTime": {
        "ns": 1584934846003434,
        "formatted": "2025-09-25T08:15:34.846Z"
      },
      "direction": "Downlink"
    }
  ]
}
```

### 2. Get Specific Flow Packet Records

```bash
curl http://localhost:8080/nwdaf-oam/flows/packet-records/192.168.1.1/192.168.1.100/80/8080
```

**Purpose**: Detailed packet analysis for troubleshooting  
**Status Code**: 200  
**Content-Type**: application/json; charset=utf-8  
**Response**: Recent packet records for the specified flow

### 3. Get All Packet Records

```bash
curl http://localhost:8080/nwdaf-oam/flows/packet-records
```

**Purpose**: Detailed packet analysis for all flows  
**Status Code**: 200  
**Content-Type**: application/json; charset=utf-8  
**Response Example**:

```json
{
  "count": 2,
  "packetRecords": [
    {
      "srcIP": "10.60.0.1",
      "dstIP": "1.1.1.1",
      "srcPort": 8,
      "dstPort": 0,
      "recentPkts": [
        {
          "timestamp": {
            "ns": 1584932832288186,
            "formatted": "2025-09-25T08:15:32.832Z"
          },
          "length": 142,
          "protocol": 1,
          "direction": "Uplink",
          "tcpFlags": 0,
          "dscpEcn": 0
        },
        {
          "timestamp": {
            "ns": 1584934840818709,
            "formatted": "2025-09-25T08:15:34.84Z"
          },
          "length": 142,
          "protocol": 1,
          "direction": "Uplink",
          "tcpFlags": 0,
          "dscpEcn": 0
        },
        {
          "timestamp": {
            "ns": 0,
            "formatted": ""
          },
          "length": 0,
          "protocol": 0,
          "direction": "Unknown",
          "tcpFlags": 0,
          "dscpEcn": 0
        }
      ]
    },
    {
      "srcIP": "1.1.1.1",
      "dstIP": "10.60.0.1",
      "srcPort": 0,
      "dstPort": 0,
      "recentPkts": [
        {
          "timestamp": {
            "ns": 1584932837860572,
            "formatted": "2025-09-25T08:15:32.837Z"
          },
          "length": 84,
          "protocol": 1,
          "direction": "Downlink",
          "tcpFlags": 0,
          "dscpEcn": 0
        },
        {
          "timestamp": {
            "ns": 1584934846005196,
            "formatted": "2025-09-25T08:15:34.846Z"
          },
          "length": 84,
          "protocol": 1,
          "direction": "Downlink",
          "tcpFlags": 0,
          "dscpEcn": 0
        }
      ]
    }
  ]
}
```

### 4. Get Total Flow Count
```bash
curl http://localhost:8080/nwdaf-oam/flows/count
```
**Purpose**: Monitor system load and resource usage  
**Status Code**: 200  
**Content-Type**: application/json; charset=utf-8  
**Response Example**:

```json
{
  "flowCount": 2
}
```

### 5. Get All Source IPs

```bash
curl http://localhost:8080/nwdaf-oam/source-ips
```

**Purpose**: Retrieve all tracked source IP addresses with statistics  
**Status Code**: 200  
**Content-Type**: application/json; charset=utf-8  
**Response Example**:

```json
{
  "count": 1,
  "source_ips": [
    {
      "ip": "10.60.0.1",
      "first_seen": {
        "ns": 1584931831468926,
        "formatted": "2025-09-25T08:15:31.831Z"
      },
      "last_seen": {
        "ns": 1584934840814597,
        "formatted": "2025-09-25T08:15:34.84Z"
      },
      "packet_count": 4,
      "byte_count": 568,
      "duration": 3009345671
    }
  ]
}
```

### 6. Get Top Source IPs

```bash
curl http://localhost:8080/nwdaf-oam/source-ips/top
```

**Purpose**: Retrieve top source IPs by traffic volume  
**Status Code**: 200  
**Content-Type**: application/json; charset=utf-8  
**Response Example**:

```json
{
  "count": 1,
  "limit": 10,
  "source_ips": [
    {
      "ip": "10.60.0.1",
      "first_seen": {
        "ns": 1584931831468926,
        "formatted": "2025-09-25T08:15:31.831Z"
      },
      "last_seen": {
        "ns": 1584934840814597,
        "formatted": "2025-09-25T08:15:34.84Z"
      },
      "packet_count": 4,
      "byte_count": 568,
      "duration": 3009345671
    }
  ]
}
```

### 7. Get Source IPs Statistics

```bash
curl http://localhost:8080/nwdaf-oam/source-ips/stats
```

**Purpose**: Retrieve aggregated statistics for all source IPs  
**Status Code**: 200  
**Content-Type**: application/json; charset=utf-8  
**Response Example**:

```json
{
  "stats": {
    "avg_bytes": 568,
    "avg_packets": 4,
    "max_bytes": 568,
    "max_packets": 4,
    "min_bytes": 568,
    "min_packets": 4,
    "total_bytes": 568,
    "total_ips": 1,
    "total_packets": 4
  }
}
```



## Data Structure Definitions

### FlowStatistics Structure

```go
type FlowStatistics struct {
    SrcIP     net.IP          `json:"srcIP"`     // Source IP address
    DstIP     net.IP          `json:"dstIP"`     // Destination IP address
    SrcPort   uint16          `json:"srcPort"`   // Source port
    DstPort   uint16          `json:"dstPort"`   // Destination port
    Protocol  uint8           `json:"protocol"`  // L4 protocol (TCP=6, UDP=17, ICMP=1)
    Cnt       int             `json:"cnt"`       // Packet count
    Bytes     uint64          `json:"bytes"`     // Total traffic in bytes
    FirstTS   utils.TimeStamp `json:"firstTime"` // First packet timestamp
    LastTS    utils.TimeStamp `json:"lastTime"`  // Last packet timestamp
    Direction string          `json:"direction"` // Flow direction: "Uplink", "Downlink", or "Unknown"
}
```

### FlowPacketRecords Structure

```go

### FlowPacketRecords Structure
```go
type FlowPacketRecords struct {
    SrcIP      net.IP         `json:"srcIP"`      // Source IP address
    DstIP      net.IP         `json:"dstIP"`      // Destination IP address
    SrcPort    uint16         `json:"srcPort"`    // Source port
    DstPort    uint16         `json:"dstPort"`    // Destination port
    RecentPkts []PacketRecord `json:"recentPkts"` // Recent packet records from ring buffer
}
```

### PacketRecord Structure

```go
type PacketRecord struct {
    TS        utils.TimeStamp `json:"timestamp"` // Packet timestamp with multiple formats
    Length    uint32          `json:"length"`    // Packet length in bytes
    Protocol  uint8           `json:"protocol"`  // L4 protocol (TCP/UDP etc.)
    Direction string          `json:"direction"` // Direction: "Uplink", "Downlink", or "Unknown"
    TCPFlags  uint8           `json:"tcpFlags"`  // TCP flags (if applicable)
    DSCP_ECN  uint8           `json:"dscpEcn"`   // DSCP/ECN value
}
```

### TimeStamp Structure
```go
type TimeStamp struct {
    NanoSeconds uint64 `json:"ns"`        // Raw timestamp in nanoseconds since system boot
    Formatted   string `json:"formatted"` // ISO 8601/RFC3339 formatted timestamp in UTC
}
```

This refactored architecture provides better API design, allowing users to choose appropriate APIs based on their specific monitoring and analysis needs.
