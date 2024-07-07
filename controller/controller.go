package controller

import (
	"webserver/http"
)

func HangleRootGet(resp http.HandlerResponse) {
	resp.SetCode(200)
	resp.Send("gdfgdf")
}
