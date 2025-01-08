package httpServer

import (
	"fmt"
	"strconv"
	"strings"
)

// mime specify yhe nature of files being trasnmited
// Content-Type: text/html

func parseData(data []byte) error {
	fmt.Println("lets parse")
	fmt.Println(data)
	fmt.Println("length of data")
	fmt.Println(len(data))

	headers := make(map[string]string)

	var reqInfo string
	for i := 0; i < len(data); i++ {
		if i > 0 && data[i] == 10 && data[i-1] == 13 {
			reqInfo = string(data[:i-1])
			data = data[i-1:]
			break
		}
	}

	reqInfoDetails := strings.Split(reqInfo, " ")
	if len(reqInfoDetails) < 3 {
		return fmt.Errorf("request should contain req method, req path, req protocol at least, we got: %v", string(reqInfo))
	}
	reqMethod := reqInfoDetails[0]
	reqPath := reqInfoDetails[1]
	reqProtocol := reqInfoDetails[2]

	startLineIndx := 0
	semicolonIndex := 0
	for i := 0; i < len(data); i++ {

		if data[i] == 58 && semicolonIndex < startLineIndx {
			semicolonIndex = i
		}
		if i > 0 && data[i] == 10 && data[i-1] == 13 {
			if i-2 > 0 && data[i-2] != 10 {
				fmt.Println("add key")
				fmt.Println(data[startLineIndx:semicolonIndex])
				fmt.Println(string(data[startLineIndx:semicolonIndex]))
				headers[string(data[startLineIndx:semicolonIndex])] = string(data[semicolonIndex+2 : i-1])

			}
			startLineIndx = i + 1
		}
	}

	var body []byte

	if val, ok := headers["Content-Length"]; ok {
		valNum, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("problem converting content length to number, err: %v", err)
		}
		if startLineIndx+valNum != len(data) {
			return fmt.Errorf("incorrect length of data, expected length of: %v, got: %v", startLineIndx+valNum, len(data))
		}
		body = data[startLineIndx : startLineIndx+valNum]
	}

	fmt.Println("haloooo")
	fmt.Println("start indx")
	fmt.Println(startLineIndx)
	// headers := line[1:]
	fmt.Println("request info")
	fmt.Println(reqInfo)
	fmt.Println("method")
	fmt.Println(reqMethod)
	fmt.Println("path")
	fmt.Println(reqPath)
	fmt.Println("protocol")
	fmt.Println(reqProtocol)
	fmt.Println("headers")
	fmt.Println(headers)

	fmt.Println("body")
	fmt.Println(string(body))

	//
	//	for _, v := range line {
	//		fmt.Println("line")
	//		fmt.Println(string(v))
	//	}

	return nil
}

func HttpHandler(data []byte) []byte {
	fmt.Println("``````````````````````````````````````")
	fmt.Println("``````````````````````````````````````")
	fmt.Println("``````````````````````````````````````")
	fmt.Println("APPLICATION DATA")
	fmt.Println(string(data))
	fmt.Println("APPLICATION DATA")
	fmt.Println("``````````````````````````````````````")
	fmt.Println("``````````````````````````````````````")
	fmt.Println("``````````````````````````````````````")
	parseData(data)

	return []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\nDate: Fri, 03 Jan 2025 12:34:56 GMT\r\n\r\nabcd")

}
