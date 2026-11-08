// macho_dyld_go.go -- Go test program for the macOS arm64 "macho/arm64dyld"
// format: Go's linker emits LC_DYLD_INFO_ONLY (rebase/bind opcodes) instead
// of chained fixups. Exercises goroutines, channels, crypto and a recovered
// panic. This file is part of the UPX executable compressor.
package main

import (
    "crypto/sha256"
    "fmt"
    "os"
    "sort"
    "sync"
)

func risky(n int) (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("recovered: %v", r)
        }
    }()
    var m map[string]int
    if n > 0 {
        m["x"] = n // nil map write panics
    }
    return nil
}

func main() {
    var wg sync.WaitGroup
    sums := make([]string, 8)
    for i := 0; i < 8; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            sums[i] = fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(i, os.Args[1:]))))[:8]
        }(i)
    }
    wg.Wait()
    sort.Strings(sums)
    ch := make(chan int, 3)
    go func() { for i := 1; i <= 3; i++ { ch <- i * i }; close(ch) }()
    t := 0
    for v := range ch { t += v }
    fmt.Println(sums, t, risky(len(os.Args)))
}
