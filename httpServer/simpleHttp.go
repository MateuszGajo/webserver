package httpServer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type httpServer struct {
	httpVersion int
}

func parseBody(contentType string, data []byte) error {
	switch string(contentType) {
	case "application/json":
		{
			var result map[string]interface{}

			err := json.Unmarshal(data, &result)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (server httpServer) parseData(data []byte) error {

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
	// reqMethod := reqInfoDetails[0]
	// reqPath := reqInfoDetails[1]
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

		val, ok := headers["Content-Type"]

		if !ok {
			panic("not ok")
		}

		parseBody(val, body)
	}

	httpVersion, err := strconv.Atoi(string(reqProtocol[5]) + string(reqProtocol[7]))
	if err != nil {
		return fmt.Errorf("problem converting http version to number, err: %v", err)
	}
	if httpVersion > server.httpVersion {
		return fmt.Errorf("newest supported version is: %v", server.httpVersion)
	}

	return nil
}

func HttpHandler(data []byte) []byte {
	server := httpServer{
		httpVersion: 11,
	}
	server.parseData(data)

	httpVersion := "HTTP/" + string(strconv.Itoa(server.httpVersion)[0]) + "." + string(strconv.Itoa(server.httpVersion)[1])
	responseCode := "200"
	responseStatus := "OK"
	reqInfo := httpVersion + " " + responseCode + " " + responseStatus + "\r\n"
	headers := "Content-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\nDate: Fri, 03 Jan 2025 12:34:56 GMT\r\n\r\n"
	datares := "abcd"

	response := reqInfo + headers + datares

	fmt.Println("response")
	fmt.Println(response)

	return []byte(response)

}
