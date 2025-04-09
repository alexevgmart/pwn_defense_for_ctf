package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type Pattern struct {
	ServiceName string `json:"service"`
	Pattern     string `json:"pattern"`
	Flag        string `json:"flag"`
	Std         any    `json:"std"`
	Active      bool   `json:"active"`
	Action      string `json:"action"`
	Warning     string `json:"WARNING,omitempty"`
}

type Patterns struct {
	Patterns []Pattern `json:"banned_patterns"`
	Count    int       `json:"count"`
}

func FindBannedPatterns(text string, std uint8, service_name string) bool {
	url := fmt.Sprintf("http://%s/api/banned-patterns?service_name=%s", server_addr, service_name)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error while request: %s\n", err.Error())
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error in response: %s\n", err.Error())
		return false
	}

	if resp.StatusCode == 200 {
		var response Patterns
		err := json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error while parsing JSON: %s", err.Error())
		}
		for _, pattern := range response.Patterns {
			if strings.Contains(pattern.Pattern, "non_printable_bytes_block") {
				continue
			}

			re := regexp.MustCompile(pattern.Pattern)

			if re.MatchString(text) {
				switch stdValue := pattern.Std.(type) {
				case float64:
					if stdValue == float64(std) {
						return true
					}
				case nil:
					return true
				}
			}
		}
	}

	return false
}

type Service struct {
	ServiceAddr string `json:"service_addr"`
	InPort      uint16 `json:"in_port"`
	ServicePort uint16 `json:"service_port"`
	IsHttp      bool   `json:"is_http"`
}

var server_addr string

func ParseServices() map[string]Service {
	url := fmt.Sprintf("http://%s/api/services", server_addr)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Couldn't get services from the server: %s", err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error in response: %s\n", err.Error())
	}

	var services map[string]Service
	err = json.Unmarshal([]byte(body), &services)
	if err != nil {
		log.Fatalf("Couldn't unmarshal json data: %s", err.Error())
	}

	return services
}

func StartPseudoProxy() {
	for service_name, service_data := range ParseServices() {
		if service_data.IsHttp {
			go func() {
				proxyAddr := fmt.Sprintf("0.0.0.0:%d", service_data.InPort)
				listener, err := net.Listen("tcp", proxyAddr)
				if err != nil {
					log.Fatalf("Couldn't start server: %s", err.Error())
				}
				defer listener.Close()

				fmt.Printf(
					"Proxying service \"%s\" (0.0.0.0:%d -> %s:%d)\n",
					service_name,
					service_data.InPort,
					service_data.ServiceAddr,
					service_data.ServicePort,
				)

				for {
					conn, err := listener.Accept()
					if err != nil {
						log.Printf("Couldn't accept connection: %s", err.Error())
						continue
					}

					go handleConnection(conn, service_data, service_name)
				}
			}()
		}
	}

	select {}
}

func SendForbidden(conn net.Conn) {
	defer conn.Close()

	response := "HTTP/1.1 403 Forbidden\r\n" +
		"Content-Type: text/plain\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"403"
	conn.Write([]byte(response))
}

type Data struct {
	Std     uint8  `json:"std"`
	DataLen uint64 `json:"dataLen"`
	Data    string `json:"data"`
}

type Stream struct {
	Request     *Data  `json:"request"`
	Response    *Data  `json:"response"`
	ServiceName string `json:"service_name"`
}

func SendDataToServer(request *string, response *string, service_name string) {
	decodedRequest, err := base64.StdEncoding.DecodeString(*request)
	if err != nil {
		log.Printf("Error while decoding request base64: %s", err.Error())
		return
	}

	requestStream := Data{
		Std:     0,
		DataLen: uint64(len(decodedRequest)),
		Data:    *request,
	}

	var stream Stream

	if response == nil {
		stream = Stream{
			Request:     &requestStream,
			Response:    nil,
			ServiceName: service_name,
		}
	} else {
		decodedResponse, err := base64.StdEncoding.DecodeString(*response)
		if err != nil {
			log.Printf("Error while decoding response base64: %s", err.Error())
			return
		}

		responseStream := Data{
			Std:     1,
			DataLen: uint64(len(decodedResponse)),
			Data:    *response,
		}

		stream = Stream{
			Request:     &requestStream,
			Response:    &responseStream,
			ServiceName: service_name,
		}
	}

	jsonData, err := json.MarshalIndent(stream, "", "  ")
	if err != nil {
		log.Printf("Error marshaling to JSON: %s", err.Error())
		return
	}

	url := fmt.Sprintf("http://%s/api/new_stream", server_addr)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error while sending stream to server: %s", err.Error())
		return
	}
	resp.Body.Close()
}

func handleConnection(conn net.Conn, service_data Service, service_name string) {
	defer conn.Close()

	var requestData bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				requestData.Write(buf[:n])
				break
			}
			log.Printf("Error reading request: %s", err.Error())
			return
		}

		requestData.Write(buf[:n])

		if n < 4096 {
			break
		}
	}
	log.Println(strings.Split(requestData.String(), "\n")[0])
	if FindBannedPatterns(requestData.String(), 0, service_name) {
		SendForbidden(conn)
		return
	}

	var newRequestData bytes.Buffer
	fromAddr := fmt.Sprintf("From: %s\n", []byte(strings.Split(conn.RemoteAddr().String(), ":")[0]))
	newRequestData.Write([]byte(fromAddr))
	newRequestData.Write(requestData.Bytes())
	encodedRequestData := base64.StdEncoding.EncodeToString(newRequestData.Bytes())

	serviceAddr := fmt.Sprintf("%s:%d", service_data.ServiceAddr, service_data.ServicePort)
	serviceConn, err := net.Dial("tcp", serviceAddr)
	if err != nil {
		log.Printf("Error connecting to service: %v", err)
		SendDataToServer(&encodedRequestData, nil, service_name)
		return
	}
	defer serviceConn.Close()

	if _, err := serviceConn.Write(requestData.Bytes()); err != nil {
		log.Printf("Error sending to service: %v", err)
		SendDataToServer(&encodedRequestData, nil, service_name)
		return
	}

	var responseData bytes.Buffer
	if _, err := io.Copy(&responseData, serviceConn); err != nil {
		log.Printf("Error reading response: %v", err)
		SendDataToServer(&encodedRequestData, nil, service_name)
		return
	}
	if FindBannedPatterns(responseData.String(), 1, service_name) {
		SendForbidden(conn)
		return
	}
	encodedResponseData := base64.StdEncoding.EncodeToString(responseData.Bytes())
	SendDataToServer(&encodedRequestData, &encodedResponseData, service_name)

	if _, err := conn.Write(responseData.Bytes()); err != nil {
		log.Printf("Error sending response: %v", err)
		return
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <web_app_ip> <web_app_port>\n", os.Args[0])
		return
	}

	server_addr = fmt.Sprintf("%s:%s", os.Args[1], os.Args[2])

	StartPseudoProxy()
}
