// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -I c -I ../../ebpf/c -fsigned-char kprobe_types.go

package ebpf

type ConnTuple struct {
	Saddr_h  uint64
	Saddr_l  uint64
	Daddr_h  uint64
	Daddr_l  uint64
	Sport    uint16
	Dport    uint16
	Netns    uint32
	Pid      uint32
	Metadata uint32
}
type TCPStats struct {
	Rtt               uint32
	Rtt_var           uint32
	State_transitions uint16
	Pad_cgo_0         [2]byte
}
type ConnStats struct {
	Sent_bytes     uint64
	Recv_bytes     uint64
	Sent_packets   uint32
	Recv_packets   uint32
	Timestamp      uint64
	Duration       uint64
	Cookie         uint32
	Protocol_stack ProtocolStack
	Flags          uint8
	Direction      uint8
	Pad_cgo_0      [6]byte
}
type Conn struct {
	Tup             ConnTuple
	Conn_stats      ConnStats
	Tcp_stats       TCPStats
	Tcp_retransmits uint32
}
type FailedConn struct {
	Tup       ConnTuple
	Reason    uint32
	Pad_cgo_0 [4]byte
}
type SkpConn struct {
	Sk  uint64
	Tup ConnTuple
}
type PidTs struct {
	Tgid      uint64
	Timestamp uint64
}
type Batch struct {
	C0        Conn
	C1        Conn
	C2        Conn
	C3        Conn
	Id        uint64
	Cpu       uint32
	Len       uint16
	Pad_cgo_0 [2]byte
}
type Telemetry struct {
	Tcp_failed_connect              uint64
	Tcp_sent_miscounts              uint64
	Unbatched_tcp_close             uint64
	Unbatched_udp_close             uint64
	Udp_sends_processed             uint64
	Udp_sends_missed                uint64
	Udp_dropped_conns               uint64
	Double_flush_attempts_close     uint64
	Double_flush_attempts_done      uint64
	Unsupported_tcp_failures        uint64
	Tcp_done_missing_pid            uint64
	Tcp_connect_failed_tuple        uint64
	Tcp_done_failed_tuple           uint64
	Tcp_finish_connect_failed_tuple uint64
	Tcp_close_target_failures       uint64
	Tcp_done_connection_flush       uint64
	Tcp_close_connection_flush      uint64
}
type PortBinding struct {
	Netns     uint32
	Port      uint16
	Pad_cgo_0 [2]byte
}
type PIDFD struct {
	Pid uint32
	Fd  uint32
}
type UDPRecvSock struct {
	Sk  uint64
	Msg uint64
}
type BindSyscallArgs struct {
	Addr uint64
	Sk   uint64
}
type ProtocolStack struct {
	Api         uint8
	Application uint8
	Encryption  uint8
	Flags       uint8
}
type ProtocolStackWrapper struct {
	Stack   ProtocolStack
	Updated uint64
}

type _Ctype_struct_sock uint64
type _Ctype_struct_msghdr uint64
type _Ctype_struct_sockaddr uint64

type TCPState uint8

const (
	Established TCPState = 0x1
	Close       TCPState = 0x7
)

type ConnFlags uint32

const (
	LInit   ConnFlags = 0x1
	RInit   ConnFlags = 0x2
	Assured ConnFlags = 0x4
)

const BatchSize = 0x4
const SizeofBatch = 0x1f0

const TCPFailureConnReset = 0x68
const TCPFailureConnTimeout = 0x6e
const TCPFailureConnRefused = 0x6f

const SizeofConn = 0x78
const SizeofFailedConn = 0x38

type ClassificationProgram = uint32

const (
	ClassificationQueues ClassificationProgram = 0x2
	ClassificationDBs    ClassificationProgram = 0x3
	ClassificationGRPC   ClassificationProgram = 0x5
)
