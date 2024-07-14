package bpf

import (
	log "github.com/sirupsen/logrus"
)

type limiter struct {
	numberOfIPsToTrack int
	topIPs             []string
	topIPsByBytes      map[string]uint64
}

func (lim *limiter) shouldProceed(ip string, bytes uint64, packets uint64) bool {
	return lim.InsertToMetadata(ip, bytes)
}

func (lim *limiter) InsertToMetadata(ip string, bytes uint64) bool /* insert success? */ {

	if lim.topIPs == nil || len(lim.topIPs) == 0 {
		log.Tracef("Creating new topIPs metadata tracker,  with %s with bytes %v", ip, bytes)
		lim.topIPs = []string{ip}
		lim.topIPsByBytes[ip] = bytes
		return true
	}

	begin, end := 0, len(lim.topIPs)-1

	maxBytes := lim.topIPsByBytes[lim.topIPs[end]]
	minBytes := lim.topIPsByBytes[lim.topIPs[begin]]

	inserted := false

	// edge cases, literally
	if bytes < minBytes {
		if len(lim.topIPs) >= lim.numberOfIPsToTrack {
			// out of space
			log.Tracef("Not considering %s with bytes %v, out of space", ip, bytes)
			return false
		}
		lim.topIPs = append([]string{ip}, lim.topIPs...)
		lim.topIPsByBytes[ip] = bytes
		inserted = true
	}
	if bytes > maxBytes {
		lim.topIPs = append(lim.topIPs, ip)
		lim.topIPsByBytes[ip] = bytes
		inserted = true
	}
	// search for the right place to insert
	for begin < end && !inserted {
		mid := ((begin + end) / 2)
		if lim.topIPsByBytes[lim.topIPs[mid]] == bytes {
			lim.topIPs = append(lim.topIPs[:mid], append([]string{ip}, lim.topIPs[mid:]...)...)
			lim.topIPsByBytes[ip] = bytes
			inserted = true
			break
		}
		// adjust perimeters
		if lim.topIPsByBytes[lim.topIPs[mid]] < bytes {
			begin = mid + 1
		} else {
			end = mid
		}
	}
	// insert if not already inserted
	if !inserted {
		lim.topIPs = append(lim.topIPs[:begin], append([]string{ip}, lim.topIPs[begin:]...)...)
		lim.topIPsByBytes[ip] = bytes
	}
	// remove the last element if we have more than we need
	if len(lim.topIPs) > lim.numberOfIPsToTrack {
		log.Tracef("Dropping %s with bytes %v, replaced by %v", lim.topIPs[len(lim.topIPs)-1], lim.topIPsByBytes[lim.topIPs[len(lim.topIPs)-1]], ip)
		lim.topIPs = lim.topIPs[1 : lim.numberOfIPsToTrack+1]
	}
	log.Tracef("current topIPs: %v", lim.topIPsByBytes)
	return true
}
