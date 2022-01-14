package main

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/Crosse/godivert"
	"github.com/getlantern/geneva/strategy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/windows"
)

var (
	qpc      uintptr
	iphlpapi *windows.LazyDLL
)

func init() {
	dll := windows.NewLazySystemDLL("kernel32.dll")
	if err := dll.Load(); err != nil {
		panic(fmt.Errorf("error loading kernel32.dll: %v", err))
	}

	_qpc := dll.NewProc("QueryPerformanceCounter")
	if err := _qpc.Find(); err != nil {
		panic(fmt.Errorf("error finding QueryPerformanceCounter: %v", err))
	}

	qpc = _qpc.Addr()

	iphlpapi = windows.NewLazySystemDLL("Iphlpapi.dll")
	if err := iphlpapi.Load(); err != nil {
		panic(fmt.Errorf("error loading Iphlpapi.dll"))
	}
}

func now() int64 {
	var now uint64

	syscall.Syscall(qpc, 1, uintptr(unsafe.Pointer(&now)), 0, 0)

	return int64(now)
}

func getAdapter(iface string) (uint32, error) {
	// https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
	// "The recommended method of calling the GetAdaptersAddresses function is to pre-allocate a
	// 15KB working buffer pointed to by the AdapterAddresses parameter. On typical computers,
	// this dramatically reduces the chances that the GetAdaptersAddresses function returns
	// ERROR_BUFFER_OVERFLOW, which would require calling GetAdaptersAddresses function multiple
	// times."
	bufLenBytes := 15 * 1024
	info := make(
		[]windows.IpAdapterAddresses,
		bufLenBytes/int(unsafe.Sizeof(windows.IpAdapterAddresses{})),
	)
	ol := uint32(bufLenBytes)

	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, &info[0], &ol)
	if err != nil {
		return 0, err
	}

	a := &info[0]
	for a != nil {
		if windows.BytePtrToString(a.AdapterName) == iface ||
			windows.UTF16PtrToString(a.FriendlyName) == iface {
			return a.IfIndex, nil
		}

		a = a.Next
	}

	return 0, fmt.Errorf("no adapter found")
}

func doIntercept(strat *strategy.Strategy, iface string) error {
	idx, err := getAdapter(iface)
	if err != nil {
		return cli.Exit(err, 1)
	}

	fmt.Fprintln(os.Stderr, "opening handle to WinDivert")
	godivert.LoadDLL("WinDivert.dll", "WinDivert.dll")

	filter := fmt.Sprintf("ifIdx == %d", idx)

	winDivert, err := godivert.OpenHandle(
		filter,
		godivert.LayerNetwork,
		godivert.PriorityDefault,
		godivert.OpenFlagFragments,
	)
	if err != nil {
		return cli.Exit(fmt.Sprintf("error initializing WinDivert: %v\n", err), 1)
	}

	fmt.Printf("intercepting traffic on %s (idx %d)\n", iface, idx)

	defer func() {
		fmt.Fprintln(os.Stderr, "closing handle")

		if err := winDivert.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "error closing WinDivert handle: %v\n", err)
		}
	}()

	packetChan, err := winDivert.Packets()
	if err != nil {
		return cli.Exit(fmt.Sprintf("error getting packets: %v\n", err), 1)
	}

	for pkt := range packetChan {
		pkt.VerifyParsed()

		var dir strategy.Direction
		if pkt.Direction() == godivert.WinDivertDirectionInbound {
			dir = strategy.DirectionInbound
		} else {
			dir = strategy.DirectionOutbound
		}

		var firstLayer gopacket.LayerType

		switch pkt.IpVersion() {
		case 4:
			firstLayer = layers.LayerTypeIPv4
		case 6:
			firstLayer = layers.LayerTypeIPv6
		default:
			fmt.Println("bypassing Geneva for non-IP packet")
			winDivert.Send(pkt)

			continue
		}

		gopkt := gopacket.NewPacket(pkt.Raw, firstLayer, gopacket.Default)

		results, err := strat.Apply(gopkt, dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error applying strategy: %v\n", err)
			winDivert.Send(pkt)

			continue
		}

		sport, _ := pkt.SrcPort()
		dport, _ := pkt.DstPort()
		fmt.Printf("%s packet (%s:%d -> %s:%d) produced %d packet(s) from strategy\n",
			dir,
			pkt.SrcIP(), sport,
			pkt.DstIP(), dport,
			len(results))

		for i, p := range results {
			newPkt := godivert.Packet{
				Raw: p.Data(),
				Addr: &godivert.WinDivertAddress{
					Timestamp: now(),
					Flags:     pkt.Addr.Flags,
					Data:      pkt.Addr.Data,
				},
				PacketLen: uint(len(p.Data())),
			}

			fmt.Printf(
				"\tinjecting packet %d/%d (len %d)\n",
				i+1,
				len(results),
				len(p.Data()),
			)

			newPkt.VerifyParsed()

			if sent, err := winDivert.Send(&newPkt); err != nil {
				fmt.Fprintf(os.Stderr, "error sending packet: %v\n", err)
			} else if sent != newPkt.PacketLen {
				fmt.Fprintf(os.Stderr, "sent %d bytes, but expected %d\n", sent, newPkt.PacketLen)
			}
		}
	}

	return nil
}
