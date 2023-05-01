package utils

import (
	"log"
	"runtime"
)

func PrintStackTrace() {
	buf := make([]byte, 1<<16)
	runtime.Stack(buf, true)
	log.Printf("%s", buf)
}
