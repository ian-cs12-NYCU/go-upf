## How to use
```
$ cd ./internal/eBPF
$ go generate 

// make UPF in free5gc directory
$ make upf
```

## Test API
```
$ curl 127.0.0.8:8000/nwdaf-oam/packets-count
```

```
[GIN-debug] GET    /nwdaf-oam/               --> github.com/free5gc/go-upf/internal/sbi.(*Server).ApplyService.(*Server).getNwdafOamRoutes.func1 (3 handlers)
[GIN-debug] GET    /nwdaf-oam/nf-resource    --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamNfResourceGet-fm (3 handlers)
[GIN-debug] GET    /nwdaf-oam/packets-count  --> github.com/free5gc/go-upf/internal/sbi.(*Server).UpfOamPacketsCountGet-fm (3 handlers)
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