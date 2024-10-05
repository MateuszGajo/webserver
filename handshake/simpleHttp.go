package handshake

import "fmt"

func HttpHandler(data []byte) {
	fmt.Println("``````````````````````````````````````")
	fmt.Println("``````````````````````````````````````")
	fmt.Println("``````````````````````````````````````")
	fmt.Println("APPLICATION DATA")
	fmt.Println(string(data))
	fmt.Println("APPLICATION DATA")
	fmt.Println("``````````````````````````````````````")
	fmt.Println("``````````````````````````````````````")
	fmt.Println("``````````````````````````````````````")
}
