# UPF eBPF Flow Analytics API Architecture

This document describes the refactored UPF eBPF flow analytics API architecture.

```
[GIN-debug] GET    /nwdaf-oam/               --> github.com/free5gc/go-upf/internal/sbi.(*Server).getNwdafOamRoutes.func1 (3 handlers)
[GIN-debug] GET    /nwdaf-oam/nf-resource    --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamNfResourceGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/packets-count  --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamPacketsCountGet-fm (3 handlers)
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

Extract detailed packet records from ring buffer for deep packet inspection. Returns recent packet details including length, protocol, direction, TCP flags, and DSCP/ECN values.

### 3. Combined Flow Data API
**GET** `/nwdaf-oam/packets-count`

Provide comprehensive flow information combining statistics and packet records (backward compatible). Returns complete flow information including both statistics and recent packet records.

### 4. Flow Count API
**GET** `/nwdaf-oam/flows/count`

Provide total number of tracked flows for resource monitoring and system health checks.

## HTTP REST API Endpoints

### Flow Statistics Endpoints
- `GET /nwdaf-oam/flows/statistics` - Retrieve all flow statistics
- `GET /nwdaf-oam/flows/statistics/{srcIP}/{dstIP}/{srcPort}/{dstPort}` - Retrieve specific flow statistics

### Packet Records Endpoints
- `GET /nwdaf-oam/flows/packet-records` - Retrieve packet records for all flows
- `GET /nwdaf-oam/flows/packet-records/{srcIP}/{dstIP}/{srcPort}/{dstPort}` - Retrieve packet records for specific flow

### Combined Data Endpoints
- `GET /nwdaf-oam/packets-count` - Retrieve combined flow data (legacy API)

### Utility Endpoints
- `GET /nwdaf-oam/flows/count` - Get total flow count

## API Usage Examples

### 1. Get All Flow Statistics
```bash
curl http://localhost:8080/nwdaf-oam/flows/statistics
```
**Purpose**: Quick overview of all active flows
**Response**: Array of flow statistics without packet details

### 2. Get Specific Flow Packet Records
```bash
curl http://localhost:8080/nwdaf-oam/flows/packet-records/192.168.1.1/192.168.1.100/80/8080
```
**Purpose**: Detailed packet analysis for troubleshooting
**Response**: Recent packet records for the specified flow

### 3. Get Total Flow Count
```bash
curl http://localhost:8080/nwdaf-oam/flows/count
```
**Purpose**: Monitor system load and resource usage
**Response**: Simple count of active flows

### 4. Get Combined Data (Backward Compatible)
```bash
curl http://localhost:8080/nwdaf-oam/packets-count
```
**Purpose**: Full flow information for comprehensive analysis
**Response**: Complete flow data with statistics and packet records

## Architecture Benefits

1. **Modular Design**: Each API focuses on specific functionality
2. **Performance Optimization**: Retrieve only required data based on use case
3. **Flexibility**: Support for both specific flow queries and bulk operations
4. **Backward Compatibility**: Preserve existing combined API
5. **Error Isolation**: Better error handling and isolation
6. **Maintainability**: Cleaner code structure, easier to maintain and extend
7. **Scalability**: More efficient resource usage for different monitoring scenarios

## File Structure

```
internal/eBPF/
├── flow_statistics.go    # Flow statistics APIs
├── packet_records.go     # Packet records APIs  
├── gtpu_counter.go      # Combined data API (refactored)
└── ebpf.go              # Core eBPF structures

internal/sbi/
├── api_nwdafoam.go      # HTTP API routes and handlers
└── processor/
    └── flowAnalytics.go # API business logic processors

pkg/utils/
└── utils.go             # Utility functions
```

## Data Structures

### [FlowStatistics](#flowstatistics-structure)
Basic flow statistics without packet details

### [FlowPacketRecords](#flowpacketrecords-structure)
Packet records from ring buffer

### [Flows](#flows-structure)
Combined flow data (statistics + packet records)

### [PacketRecord](#packetrecord-structure)
Individual packet information

---

## Data Structure Definitions

### FlowStatistics Structure
```go
type FlowStatistics struct {
    SrcIP   net.IP          `json:"srcIP"`     // Source IP address
    DstIP   net.IP          `json:"dstIP"`     // Destination IP address
    SrcPort uint16          `json:"srcPort"`   // Source port
    DstPort uint16          `json:"dstPort"`   // Destination port
    Cnt     int             `json:"cnt"`       // Packet count
    Bytes   uint64          `json:"bytes"`     // Total traffic in bytes
    FirstTS utils.TimeStamp `json:"firstTime"` // First packet timestamp
    LastTS  utils.TimeStamp `json:"lastTime"`  // Last packet timestamp
}
```

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

### Flows Structure
```go
type Flows struct {
    SrcIP      net.IP          `json:"srcIP"`      // Source IP address
    DstIP      net.IP          `json:"dstIP"`      // Destination IP address
    SrcPort    uint16          `json:"srcPort"`    // Source port
    DstPort    uint16          `json:"dstPort"`    // Destination port
    Cnt        int             `json:"cnt"`        // Packet count
    Bytes      uint64          `json:"bytes"`      // Total traffic in bytes
    FirstTS    utils.TimeStamp `json:"firstTime"`  // First packet timestamp
    LastTS     utils.TimeStamp `json:"lastTime"`   // Last packet timestamp
    RecentPkts []PacketRecord  `json:"recentPkts"` // Recent packet records from ring buffer
}
```

### PacketRecord Structure
```go
type PacketRecord struct {
    TS        utils.TimeStamp `json:"timestamp"` // Packet timestamp with multiple formats
    Length    uint32          `json:"length"`    // Packet length in bytes
    Protocol  uint8           `json:"protocol"`  // L4 protocol (TCP/UDP etc.)
    Direction uint8           `json:"direction"` // Direction (0=unknown, 1=ingress, 2=egress)
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

This refactored architecture provides better API design, allowing users to choose appropriate APIs based on their needs while maintaining backward compatibility.
