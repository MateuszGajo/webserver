package parser

import (
	"testing"
	"webserver/http"
)

func TestParseOnlyRequestLine(t *testing.T) {
	req := "GET / HTTP/1.1\r\n" +
		"\r\n"

	resp := ParseRequest(req)

	if len(resp.Headers) != 0 || len(resp.Content) != 0 {
		t.Fatalf("Header and content should be empty, insted we got: %q, :%q", resp.Headers, resp.Content)
	}

}

func TestParseRequest(t *testing.T) {
	req := "GET / HTTP/1.1\r\n" +
		"Accept: */*\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n"

	resp := ParseRequest(req)

	reqMethod := resp.RequestLine.ReqType
	reqMethodExpect := string(http.GET)

	if reqMethod != reqMethodExpect {
		t.Fatalf("We expect protocol:%v, we got:%v", reqMethodExpect, reqMethod)
	}

	reqProtocol := resp.RequestLine.ProtocolVersion
	reqProtocolExpect := "HTTP/1.1"

	if reqProtocol != reqProtocolExpect {
		t.Fatalf("We expect protocol:%v, we got:%v", reqProtocolExpect, reqProtocol)
	}

	reqPath := resp.RequestLine.Path
	reqPathExpect := "/"

	if reqPath != reqPathExpect {
		t.Fatalf("We expect path:%v, we got:%v", reqPathExpect, reqPath)
	}

	if len(resp.Headers) != 2 {
		t.Fatalf("should be only 2 parsed headers fields: %q", resp.Headers)
	}

	acceptHeaderFieldExpectValue := "*/*"
	acceptHeaderFieldValue := resp.Headers["Accept"]

	if acceptHeaderFieldValue != acceptHeaderFieldExpectValue {
		t.Fatalf("Accept header field should have value: %q, insted we got:%v", acceptHeaderFieldExpectValue, acceptHeaderFieldValue)
	}

	connecionHeaderFieldExpectValue := "keep-alive"
	connectionHeaderFieldValue := resp.Headers["Connection"]

	if connectionHeaderFieldValue != connecionHeaderFieldExpectValue {
		t.Fatalf("Connection header field should have value: %q, insted we got:%v", connectionHeaderFieldValue, connecionHeaderFieldExpectValue)
	}
}
