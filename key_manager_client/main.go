package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"key_manager_client/client"
	"log"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "10.10.21.31:12345", "address ")
	flag.Parse()
	if !flag.Parsed() {
		flag.Usage()
		os.Exit(1)
	}
	c := client.NewKmClient(*addr)
	for i := 0; i < 10; i++ {
		pri, _ := ioutil.ReadFile("test.key")
		pub, _ := ioutil.ReadFile("test.pub")
		s, err := c.IssueCert("wuhaibo", string(pub))
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println("private key:")
		fmt.Println(string(pri))
		fmt.Println("cert:")
		fmt.Println(s)
		time.Sleep(time.Millisecond * 500)
	}
}
