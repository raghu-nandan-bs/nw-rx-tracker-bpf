package bpf

import (
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

var bpfObjects burst_trackrObjects
var cpuCount int
var collectorLock *sync.Mutex

func init() {
	cpuCount, _ = ebpf.PossibleCPU()
	collectorLock = &sync.Mutex{}
}

func RemoveMemolock() error {
	return rlimit.RemoveMemlock()
}

// loads bpf object file internally
func LoadObjects() error {
	if err := loadBurst_trackrObjects(&bpfObjects, nil); err != nil {
		return err
	}
	return nil
}

// Close cleans up the bpf objects
func CloseObjects() error {
	return bpfObjects.Close()
}

// given a device name, links the xdp program to the device
// returns a cleanup function to unlink the xdp program
// add it to the "defer" stack
func LinkXDPProgramToDevice(deviceName string) (func(), error) {

	cleanupFunc := func() {
		// nothing to do as yet
	}

	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return cleanupFunc, err
	}

	linked, err := link.AttachXDP(link.XDPOptions{
		Program:   bpfObjects.MsrPkts,
		Interface: iface.Index,
	})
	if err != nil {
		return cleanupFunc, err
	}
	cleanupFunc = func() {
		linked.Close()
	}

	return cleanupFunc, err
}

// tracks ingress packets,
// and reports every "x" time interval
// returns a channel to receive the stats
func TrackIngress(interval time.Duration, stopChan chan bool) chan IngressStatsProcessed {
	stats := make(chan IngressStatsProcessed, 1)

	process := func() {

		var collected = newIngressStatsProcessed(3)

		IngestIPV4Objects(&collected)
		IngestIPV6Objects(&collected)

		stats <- collected
	}

	tick := time.Tick(interval)
	go func() {
		for {
			select {
			case <-tick:
				process()
			case <-stopChan:
				break
			}
		}
	}()

	return stats

}

func injestObject(key []byte, values []burst_trackrFlowData, collector *IngressStatsProcessed) {
	var ip net.IP
	if len(key) == 4 {
		ip = make(net.IP, 4)
		copy(ip, key)
	} else if len(key) == 16 {
		ip = make(net.IP, 16)
		copy(ip, key)
	}

	var nwInfo PacketStats
	nwInfo.Bytes = uint64(0)
	nwInfo.Packets = uint64(0)

	for _, v := range values {
		nwInfo.Bytes += v.RxBytes
		nwInfo.Packets += v.RxPackets
	}
	// cleanup the original object
	bpfObjects.FlowTrackr.Delete(key)

	collectorLock.Lock()
	collector.Ingest(ip, nwInfo)
	collectorLock.Unlock()
}

func IngestIPV4Objects(collector *IngressStatsProcessed) {
	// we cant make updates to the map while iterating
	// so we clone the map, and iterate over the clone
	trackerMap, err := bpfObjects.FlowTrackr.Clone()
	if err != nil {
		log.Errorf("[iteration failed] Error cloning ebpf map: %v", err)
	}
	iter := trackerMap.Iterate()

	nextKey := make([]byte, 4)
	values := make([]burst_trackrFlowData, cpuCount)

	for {
		if !iter.Next(&nextKey, &values) {
			break
		}
		// get the latest value, and clear the item in original map
		bpfObjects.FlowTrackr.LookupAndDelete(&nextKey, &values)
		// @TODO: prallelize this with schedulable runners
		injestObject(nextKey, values, collector)
	}
}

func IngestIPV6Objects(collector *IngressStatsProcessed) {
	// we cant make updates to the map while iterating
	// so we clone the map, and iterate over the clone
	trackerMap, err := bpfObjects.FlowTrackrIpv6.Clone()
	if err != nil {
		log.Errorf("[iteration failed] Error cloning ebpf map: %v", err)
	}
	iter := trackerMap.Iterate()
	nextKey := make([]byte, 16)
	values := make([]burst_trackrFlowData, cpuCount)
	for {
		if !iter.Next(&nextKey, &values) {
			break
		}
		// get the latest value, and clear the item in original map
		bpfObjects.FlowTrackrIpv6.LookupAndDelete(&nextKey, &values)
		// @TODO: prallelize this with schedulable runners
		injestObject(nextKey, values, collector)
	}
}
