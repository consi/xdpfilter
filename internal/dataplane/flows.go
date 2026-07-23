// SPDX-License-Identifier: GPL-2.0

package dataplane

import (
	"encoding/binary"
	"log"
	"net"

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
		vlans := binary.LittleEndian.Uint32(key[12:16]) // numeric field, native order
		age := uint32(0)
		if now >= val.LastSeen {
			age = ticksToSec(now - val.LastSeen)
		}
		fi := FlowInfo{
			Proto:    proto,
			InetIP:   net.IP(append([]byte(nil), key[0:4]...)), // bytes are network order
			HostIP:   net.IP(append([]byte(nil), key[4:8]...)),
			InetPort: binary.BigEndian.Uint16(key[8:10]),
			HostPort: binary.BigEndian.Uint16(key[10:12]),
			OuterVID: uint16((vlans >> 12) & 0x0FFF),
			State:    stateName(val.State),
			AgeSec:   age,
		}
		out = append(out, fi)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if err := it.Err(); err != nil {
		log.Printf("flows: iterate: %v", err)
	}
	return out
}
