// SPDX-License-Identifier: GPL-2.0

package dataplane

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// FlowInfo is a decoded flow-table entry for `xdpfilter flows`.
type FlowInfo struct {
	Proto    string
	InetIP   net.IP
	HostIP   net.IP
	InetPort uint16
	HostPort uint16
	OuterVID uint16
	State    string
	AgeSec   uint32
}

// FlowQuery bounds and filters a flow-table scan. ScanLimit prevents an
// interactive client from walking a multi-million-entry table accidentally.
type FlowQuery struct {
	Protocol  string
	VLAN      int
	Text      string
	Limit     int
	ScanLimit int
}

// FlowScan is a bounded snapshot for interactive flow browsing.
type FlowScan struct {
	Rows      []FlowInfo
	Scanned   int
	Truncated bool
}

// ScanFlows scans TCP and/or UDP maps with a hard visit limit.
func ScanFlows(s *SharedMaps, q FlowQuery) (FlowScan, error) {
	if q.Limit <= 0 {
		q.Limit = 200
	}
	if q.ScanLimit <= 0 {
		q.ScanLimit = 10000
	}
	q.Protocol = strings.ToUpper(strings.TrimSpace(q.Protocol))
	needle := strings.ToLower(strings.TrimSpace(q.Text))
	var out FlowScan
	for _, src := range []struct {
		name string
		m    *ebpf.Map
	}{{"TCP", s.Flows}, {"UDP", s.UDPFlows}} {
		if q.Protocol != "" && q.Protocol != "ALL" && q.Protocol != src.name {
			continue
		}
		now := MonotonicTick()
		var key [16]byte
		var val flowVal
		it := src.m.Iterate()
		for it.Next(&key, &val) {
			out.Scanned++
			if out.Scanned > q.ScanLimit {
				out.Truncated = true
				break
			}
			fi := decodeFlow(key, val, src.name, now)
			if q.VLAN >= 0 && int(fi.OuterVID) != q.VLAN {
				continue
			}
			if needle != "" {
				hay := strings.ToLower(strings.Join([]string{fi.Proto, fi.HostIP.String(), fi.InetIP.String(), strconv.Itoa(int(fi.HostPort)), strconv.Itoa(int(fi.InetPort)), fi.State}, " "))
				if !strings.Contains(hay, needle) {
					continue
				}
			}
			out.Rows = append(out.Rows, fi)
			if len(out.Rows) >= q.Limit {
				out.Truncated = true
				break
			}
		}
		if err := it.Err(); err != nil {
			return out, fmt.Errorf("scan %s flows: %w", src.name, err)
		}
		if out.Truncated {
			break
		}
	}
	return out, nil
}

func decodeFlow(key [16]byte, val flowVal, proto string, now uint32) FlowInfo {
	vlans := binary.LittleEndian.Uint32(key[12:16])
	age := uint32(0)
	if now >= val.LastSeen {
		age = ticksToSec(now - val.LastSeen)
	}
	return FlowInfo{
		Proto: proto, InetIP: net.IP(append([]byte(nil), key[0:4]...)), HostIP: net.IP(append([]byte(nil), key[4:8]...)),
		InetPort: binary.BigEndian.Uint16(key[8:10]), HostPort: binary.BigEndian.Uint16(key[10:12]),
		OuterVID: uint16((vlans >> 12) & 0x0FFF), State: stateName(val.State), AgeSec: age,
	}
}

func stateName(s uint8) string {
	switch s {
	case stSynSent:
		return "SYN_SENT"
	case stSynRcvd:
		return "SYN_RCVD"
	case stEst:
		return "EST"
	case stClosing:
		return "CLOSING"
	case stUdp:
		return "UDP"
	default:
		return "NONE"
	}
}

// DumpFlows returns up to limit decoded entries from a flow map (limit<=0 = all).
func DumpFlows(m *ebpf.Map, proto string, limit int) []FlowInfo {
	now := MonotonicTick()
	var key [16]byte
	var val flowVal
	var out []FlowInfo

	it := m.Iterate()
	for it.Next(&key, &val) {
		out = append(out, decodeFlow(key, val, proto, now))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if err := it.Err(); err != nil {
		log.Printf("flows: iterate: %v", err)
	}
	return out
}
