## 架構一覽

1. eBPF（XDP/TC 掛在 UPF 的 N6/N3/N9 需要的位置）：
    - 解析封包 → 萃取輕量欄位 → **打包成 event** → **丟進全域 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`**。
    - 不做重運算，只做抽樣/限流與失敗計數。
2. Go 使用者態：
    - 開 perf reader，阻塞讀事件。
    - 以 `map[FlowKey] → 環形佇列（容量 K 可動態）` 維護「每 flow 最近 K 包」。
    - 週期性把每 flow 的彙總（`cnt/bytes/first/last/recentPkts`…）輸出成你的 `connList` JSON。


## How to use
```
$ cd ./internal/eBPF
$ go generate 

// make UPF in free5gc directory
$ make upf
```

## Test API
```
# Original APIs
$ curl 127.0.0.8:8000/nwdaf-oam/packets-count | jq
$ curl 127.0.0.8:8000/nwdaf-oam/source-ips | jq

# New Flow Analytics APIs
$ curl 127.0.0.8:8000/nwdaf-oam/flows/statistics | jq
$ curl 127.0.0.8:8000/nwdaf-oam/flows/packet-records | jq
$ curl 127.0.0.8:8000/nwdaf-oam/flows/count | jq

# Specific flow queries
$ curl 127.0.0.8:8000/nwdaf-oam/flows/statistics/192.168.1.1/192.168.1.100/80/8080 | jq
$ curl 127.0.0.8:8000/nwdaf-oam/flows/packet-records/192.168.1.1/192.168.1.100/80/8080 | jq
```

```
[GIN-debug] GET    /nwdaf-oam/               --> github.com/free5gc/go-upf/internal/sbi.(*Server).getNwdafOamRoutes.func1 (3 handlers)
[GIN-debug] GET    /nwdaf-oam/nf-resource    --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamNfResourceGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/packets-count  --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamPacketsCountGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/statistics --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamFlowStatisticsGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/statistics/:srcIP/:dstIP/:srcPort/:dstPort --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamFlowStatisticsByKeyGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/packet-records --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamPacketRecordsGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/packet-records/:srcIP/:dstIP/:srcPort/:dstPort --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamPacketRecordsByKeyGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/flows/count     --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamFlowCountGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips     --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPsGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips/:ip --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPByIPGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips/count --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPsCountGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips/top --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamTopSourceIPsGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/source-ips/stats --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPsStatsGet-fm (3 handlers)
[GIN-debug] DELETE /nwdaf-oam/source-ips     --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamSourceIPsClear-fm (3 handlers)
```

### Debug
install bpftool: 
```
$ sudo apt install linux-tools-$(uname -r)
$ /usr/lib/linux-tools/5.15.0-139-generic/bpftool

```

Open bpftool in one terminal
```
$sudo bpftool prog tracelog
```

Run another terminal

#### Check eBPF Program Status
```bash
# Check all loaded eBPF programs
sudo bpftool prog list

# Check XDP programs attached to interfaces
sudo bpftool net list

# Check TC programs on specific interfaces
sudo tc filter show dev enp0s3 egress
sudo tc filter show dev upfgtp egress

# Check TC qdisc status
sudo tc qdisc show dev upfgtp
sudo tc qdisc show dev enp0s3
```

#### Monitor eBPF Program Output
Open bpftool in one terminal
```
$ sudo bpftool prog tracelog
```

clean trace log
```
# 清空 trace buffer
# 執行前 - 查看 trace 內容
$ sudo cat /sys/kernel/debug/tracing/trace | wc -l

$ sudo sh -c 'echo > /sys/kernel/debug/tracing/trace'
```

## Performance Optimization Mechanisms

### Dual-Layer Control System

The eBPF probe implements a sophisticated dual-layer control system to optimize performance under high traffic loads:

#### 1. Sampling Control (sample_rate)
- **Purpose**: Controls which packets are processed and recorded
- **Implementation**: Time-based modulo sampling using `(timestamp / 1000) % sample_rate`
- **Examples**:
  - `sample_rate = 1`: Process all packets (100% sampling)
  - `sample_rate = 8`: Process ~1/8 of packets (12.5% sampling)
  - `sample_rate = 16`: Process ~1/16 of packets (6.25% sampling)

#### 2. Wake-up Control (event_counter)
- **Purpose**: Controls when to wake up userspace for event processing
- **Implementation**: Per-CPU counter with `WAKE_UP_INTERVAL = 16`
- **Mechanism**: Userspace is awakened every 16 events, enabling batch processing

### Packet Processing Workflow

```
Packet Arrival → Sampling Check → Flow Statistics → Event Creation → 
Counter Increment → Wake-up Decision → Batch Processing in Userspace
```

1. **Sampling Check**: Packet passes through `should_sample_packet()` filter
2. **Flow Recording**: If sampled, update flow statistics in eBPF maps
3. **Event Creation**: Create packet event structure
4. **Counter Management**: Increment per-CPU event counter
5. **Conditional Wake-up**: Wake userspace only when `counter % 16 == 0`
6. **Batch Processing**: Userspace processes multiple events per wake-up

### Performance Benefits

#### A. Sampling Reduces Processing Load
- Processes only a subset of packets during high traffic
- Reduces eBPF program computational overhead
- Minimizes map update operations

#### B. Wake-up Control Reduces Context Switching
- Batches multiple events before userspace notification
- Reduces kernel/userspace switching overhead
- Improves overall system throughput

### Real-world Example

In a high-traffic environment:
```
Original Traffic:     100,000 pps (packets per second)
↓ sample_rate = 10   (10% sampling)
Processed Packets:    10,000 pps
↓ WAKE_UP_INTERVAL = 16   (batch processing)
Wake-up Frequency:    625 times/second (10,000 ÷ 16)
```

This design maintains monitoring capabilities while significantly reducing system load.