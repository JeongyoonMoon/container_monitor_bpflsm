package main

import "C"
import (
	"strconv"
)

//export LookupContainerID
func LookupContainerID (pid uint32) *C.char {
	str := "Hello World from Go pid: " + strconv.FormatUint(uint64(pid), 10)
	cstr := C.CString(str)
	return cstr
}

func main() {}
