package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jschwinger233/elibpcap"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf main.bpf.c -- -I../headers

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func tracePipeListen(ctx context.Context) error {
	f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		return fmt.Errorf("failed to open trace pipe: %w", err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	b := make([]byte, 1024)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		l, err := r.Read(b)
		if err != nil {
			return fmt.Errorf("failed to read from trace pipe: %w", err)
		}

		s := string(b[:l])
		fmt.Println(s)
	}
}

func injectFilter(spec *ebpf.CollectionSpec, expr string) error {
	if expr == "" {
		return nil
	}
	log.Printf("inject pcap filter: %s", expr)

	oldInsts := spec.Programs["sample_prog"].Instructions
	newInsts, err := elibpcap.Inject(expr, oldInsts, elibpcap.Options{
		AtBpf2Bpf:  "pcap_filter",
		DirectRead: true,
		L2Skb:      true,
	})
	if err != nil {
		return err
	}

	spec.Programs["sample_prog"].Instructions = newInsts
	return nil
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	var expr string
	if len(os.Args) > 1 {
		expr = strings.TrimSpace(strings.Join(os.Args[1:], " "))
	}
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatal(err)
	}

	if err := injectFilter(spec, expr); err != nil {
		log.Fatal(err)
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		ve := &ebpf.VerifierError{}
		if errors.As(err, &ve) {
			log.Printf("verifier error: %+v", ve)
		}
		log.Printf("%+v", err)
		return
	}
	defer objs.Close()

	tcIface := "lo"
	devID, err := net.InterfaceByName(tcIface)
	if err != nil {
		log.Println(err)
		return
	}
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.SampleProg,
		Interface: devID.Index,
	})
	if err != nil {
		log.Println(err)
		return
	}
	defer lnk.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	log.Println("...")
	go func() {
		if err := tracePipeListen(ctx); err != nil {
			log.Printf("Error: %v", err)
			stop()
		}
	}()
	<-ctx.Done()
	log.Println("bye bye")
}
