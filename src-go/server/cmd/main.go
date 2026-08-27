package main

import "C"

import (
	"flag"
	"fmt"
	"log"
	"server"
	"strings"
)

func main() {
	spoofAddr := flag.String("spoof", "", "Spoof proxy address to listen on ([ip:]port)")
	flag.Parse()

	log.Fatalln(server.StartServer(*spoofAddr))
}

//export StartServer
func StartServer(spoofAddr *C.char) *C.char {
	if err := server.StartServer(C.GoString(spoofAddr)); err != nil {
		return C.CString(err.Error())
	}
	return C.CString("")
}

//export StopServer
func StopServer() *C.char {
	if err := server.StopServer(); err != nil {
		return C.CString(err.Error())
	}
	return C.CString("")
}

//export SmokeTest
func SmokeTest() {
	fmt.Println("smoke test success")
}

//export GetFingerprints
func GetFingerprints() *C.char {
	return C.CString(strings.Join(server.GetFingerprints(), "\n"))
}

// GetRuntimeStatus reports what the Go side is actually doing, as JSON.
//
// Deliberately separate from TransportConfig: that struct is matched field-for-field with its Java
// twin on every request, and adding status fields to it would change a two-language contract for
// something that is read occasionally and is not part of a request at all. See ADR-0001 section 3.
//
//export GetRuntimeStatus
func GetRuntimeStatus() *C.char {
	return C.CString(server.RuntimeStatusJSON())
}
