package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
)

func main() {
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: customTransport,
	}

	// Make a GET request to the server with a self-signed certificate
	res, err := client.Get("https://localhost:4221/get")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer res.Body.Close()

	jsonData := `{"key1":"value1", "key2":"value2"}`

	res, err = client.Post("https://localhost:4221/post", "application/json", bytes.NewBuffer([]byte(jsonData)))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer res.Body.Close()

	fmt.Println("Response Status:", res.Status)
}
