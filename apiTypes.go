package bpf

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

const (
	IPProtoV4 = "ipv4"
	IPProtoV6 = "ipv6"
)

type PacketStats struct {
	Packets uint64
	Bytes   uint64
}

func (ps PacketStats) BytesAsHumanReadableStr() string {
	// convert bytes to human readable format
	const unit = 1024
	if ps.Bytes < unit {
		return fmt.Sprintf("%d B", ps.Bytes)
	}
	div, exp := int64(unit), 0
	for n := ps.Bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(ps.Bytes)/float64(div), "KMGTPE"[exp])
}

type IngressStat struct {
	SourceIP   net.IP
	IPProtocol string
	PacketStats
}

func (s IngressStat) PacketCount() uint64 {
	return s.Packets
}

func (s IngressStat) ByteCount() uint64 {
	return s.Bytes
}

func (s IngressStat) IP() net.IP {
	return s.SourceIP
}

type IngressStatsProcessed struct {
	IPV4Stats        PacketStats
	IPV6Stats        PacketStats
	BySourceIPv4Addr map[string]PacketStats
	BySourceIPv6Addr map[string]PacketStats
	AggrStats        PacketStats
	limiter          limiter
}

func newIngressStatsProcessed(topIPsToTrack int) IngressStatsProcessed {
	return IngressStatsProcessed{
		BySourceIPv4Addr: make(map[string]PacketStats),
		BySourceIPv6Addr: make(map[string]PacketStats),
		limiter: limiter{
			numberOfIPsToTrack: topIPsToTrack,
			topIPsByBytes:      make(map[string]uint64),
		},
	}
}

func (sp *IngressStatsProcessed) Ingest(ip net.IP, p PacketStats) {

	sp.AggrStats.Bytes += p.Bytes
	sp.AggrStats.Packets += p.Packets

	// no need to track IP Wise, if we are not going to display it
	if !sp.limiter.shouldProceed(ip.String(), p.Bytes, p.Packets) {
		return
	}

	if len(ip) == 4 {
		sp.IPV4Stats.Bytes += p.Bytes
		sp.IPV4Stats.Packets += p.Packets
		sip := ip.String()
		if val, ok := sp.BySourceIPv4Addr[sip]; ok {
			val.Bytes += p.Bytes
			val.Packets += p.Packets
			sp.BySourceIPv4Addr[sip] = val
		} else {
			if sp.BySourceIPv4Addr == nil {
				sp.BySourceIPv4Addr = make(map[string]PacketStats)
			}
			sp.BySourceIPv4Addr[sip] = p
		}
		return
	} else if len(ip) == 16 {
		sp.IPV6Stats.Bytes += p.Bytes
		sp.IPV6Stats.Packets += p.Packets
		sip := ip.String()
		if val, ok := sp.BySourceIPv6Addr[sip]; ok {
			val.Bytes += p.Bytes
			val.Packets += p.Packets
			sp.BySourceIPv6Addr[sip] = val
		} else {
			if sp.BySourceIPv6Addr == nil {
				sp.BySourceIPv6Addr = make(map[string]PacketStats)
			}
			sp.BySourceIPv6Addr[sip] = p
		}
		return
	}
	log.Errorf("Unknown packet data recieved: src ip[%v], len:%v, size: %v", ip.String(), len(ip), p.BytesAsHumanReadableStr())
}
