package http

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPartialMsg(t *testing.T) {
	msg := []byte{byte(TLSContentTypeHandshake), 3, 0}
	output, partialOut, _ := Parser(msg)

	if len(output) > 1 {
		t.Errorf("Output should be empty")
	}

	if !reflect.DeepEqual(msg, partialOut) {
		t.Errorf("Should return whole msg as partial, Expected: %v insted we got: %v", msg, partialOut)
	}
}

func TestFullAndPartialMsg(t *testing.T) {
	fullMsg := []byte{byte(TLSContentTypeHandshake), 3, 0, 0, 2, 1, 0}
	partialMsg := []byte{byte(TLSContentTypeHandshake), 3, 0}
	msg := append(fullMsg, partialMsg...)

	output, partialOut, _ := Parser(msg)

	if !reflect.DeepEqual(fullMsg, output[0]) {
		t.Errorf("output should have fullMsg content at index 0. Expected: %v insted we got: %v", fullMsg, output[0])
	}

	if !reflect.DeepEqual(partialMsg, partialOut) {
		t.Errorf("Should return whole msg as partial, Expected: %v insted we got: %v", partialMsg, partialOut)
	}
}

func TestErrorWrongContentType(t *testing.T) {
	msg := []byte{12, 3, 0, 0, 2, 1, 0}

	_, _, err := Parser(msg)

	fmt.Print(err)

	expectedErr := "invalid content type"

	if err == nil {
		t.Error("It should return error")
	}

	if err != nil && err.Error() != expectedErr {
		t.Errorf("Expected error to be: %v, got: %v", expectedErr, err.Error())
	}

}

func TestParseMultipleMsg(t *testing.T) {
	fullMsgOne := []byte{byte(TLSContentTypeHandshake), 3, 0, 0, 2, 1, 0}
	fullMsgTwo := []byte{byte(TLSContentTypeHandshake), 3, 0, 0, 2, 4, 5}
	msg := append(fullMsgOne, fullMsgTwo...)

	output, _, _ := Parser(msg)

	if !reflect.DeepEqual(fullMsgOne, output[0]) {
		t.Errorf("output should have fullMsg content at index 0. Expected: %v insted we got: %v", fullMsgOne, output[0])
	}

	if !reflect.DeepEqual(fullMsgTwo, output[1]) {
		t.Errorf("output should have fullMsg content at index 0. Expected: %v insted we got: %v", fullMsgTwo, output[0])
	}
}
