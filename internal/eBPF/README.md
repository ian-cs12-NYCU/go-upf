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