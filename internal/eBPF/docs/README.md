## 架構一覽

1. eBPF（XDP/TC 掛在 UPF 的 N6/N3/N9 需要的位置）：
    - 解析封包 → 萃取輕量欄位 → **打包成 event** → **丟進全域 `BPF_MAP_TYPE_RINGBUF`**。
    - 不做重運算，只做抽樣/限流與失敗計數。
2. Go 使用者態：
    - 開 ringbuf reader，阻塞讀事件。
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