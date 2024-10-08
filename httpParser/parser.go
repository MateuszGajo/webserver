package httpParser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"webserver/http"
)

type RequestLine struct {
	ReqType         string
	Path            string
	ProtocolVersion string
}

type RequestDetails struct {
	RequestLine RequestLine
	Headers     map[string]string
	Content     map[string]interface{}
}

func parseHeader(header string) map[string]string {
	headerItems := strings.Split(header[:len(header)-(len("\r\n")*2)], "\r\n")

	headerKeyVal := make(map[string]string)
	for _, v := range headerItems {
		headerSplit := strings.Split(v, ": ")

		if len(headerSplit) < 2 {
			fmt.Print("Invalid header")
			os.Exit(1)
		}
		headerKeyVal[headerSplit[0]] = headerSplit[1]
	}

	return headerKeyVal
}

func parseRequestLine(msg string) RequestLine {
	msgSplitted := strings.Split(msg[:len(msg)-len("\r\n")], " ")

	return RequestLine{
		ReqType:         msgSplitted[0],
		Path:            msgSplitted[1],
		ProtocolVersion: msgSplitted[2],
	}
}

func parseContent(contentType http.ContentType, data string) map[string]interface{} {
	switch contentType {
	case http.APPLICATION_JSON:
		return parseContentApplicationJson(data)
	default:
		return parseContentApplicationJson(data)
	}

}

func parseContentApplicationJson(data string) map[string]interface{} {
	var result map[string]interface{}

	if len(data) == 0 {
		return make(map[string]interface{})
	}

	err := json.Unmarshal([]byte(data), &result)

	if err != nil {
		fmt.Printf("can convert data, err: %v", err)
	}

	return result

}

func ParseRequest(request string) RequestDetails {
	index := strings.Index(request, "\r\n")
	if index == -1 || len(request) < index+len("\r\n") {
		fmt.Print("can't convert request line")
		return RequestDetails{}
	}
	requestLine := request[:index+len("\r\n")]
	requestLineParsed := parseRequestLine(requestLine)

	request = request[index+len("\r\n"):]
	index = strings.Index(request, "\r\n\r\n")

	if index == -1 || len(request) < index+len("\r\n\r\n") {
		fmt.Print("can't convert header")
		return RequestDetails{
			RequestLine: requestLineParsed,
		}
	}

	headersData := request[:index+len("\r\n\r\n")]
	headers := parseHeader(headersData)

	content := request[index+len("\r\n\r\n"):]

	return RequestDetails{
		RequestLine: requestLineParsed,
		Headers:     headers,
		Content:     parseContent(http.ContentType(headers["Content-Type"]), content),
	}
}
