package models

const (
	Success string = "success"
	Error   string = "error"
)

type ResponseData struct {
	Message string      `json:"message"`
	Status  string      `json:"status"`
	Data    interface{} `json:"data"`
}
