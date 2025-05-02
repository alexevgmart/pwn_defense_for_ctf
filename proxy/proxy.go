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
	"time"
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

type Service struct {
	ServiceAddr string `json:"service_addr"`
	InPort      uint16 `json:"in_port"`
	ServicePort uint16 `json:"service_port"`
	IsHttp      bool   `json:"is_http"`
	Protocol    string `json:"protocol"`
}

var server_addr string

type StreamData struct {
	Std     uint8  `json:"std"`
	DataLen uint64 `json:"dataLen"`
	Data    string `json:"data"`
}

type StreamHttp struct {
	Request     *StreamData `json:"request"`
	Response    *StreamData `json:"response"`
	ServiceName string      `json:"service_name"`
	IsHttp      bool        `json:"is_http"`
}

type StreamTcp struct {
	Stream      []StreamData `json:"stream"`
	ServiceName string       `json:"service_name"`
	RemoteAddr  string       `json:"remote_addr"`
	IsHttp      bool         `json:"is_http"`
}

type TmpStreamData struct {
	Std  uint8
	Data bytes.Buffer
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
		fmt.Printf(
			"Proxying service \"%s\" (%s) (0.0.0.0:%d -> %s:%d)\n",
			service_name,
			service_data.Protocol,
			service_data.InPort,
			service_data.ServiceAddr,
			service_data.ServicePort,
		)

		if strings.Contains(service_data.Protocol, "tcp") {
			go func() {
				proxyAddr := fmt.Sprintf("0.0.0.0:%d", service_data.InPort)
				listener, err := net.Listen("tcp", proxyAddr)
				if err != nil {
					log.Fatalf("Couldn't start server: %s", err.Error())
				}
				defer listener.Close()

				for {
					conn, err := listener.Accept()
					if err != nil {
						log.Printf("Couldn't accept connection: %s", err.Error())
						continue
					}

					go handleTcpConnection(conn, service_data, service_name)
					// if service_data.IsHttp {
					// 	go handleHttpConnection(conn, service_data, service_name)
					// } else {
					// 	go handleTcpConnection(conn, service_data, service_name)
					// }
				}
			}()
		} else if strings.Contains(service_data.Protocol, "udp") {
			go func() {
				proxyAddr := fmt.Sprintf("0.0.0.0:%d", service_data.InPort)
				udpAddr, err := net.ResolveUDPAddr("udp", proxyAddr)
				if err != nil {
					log.Printf("ResolveUDPAddr failed: %s\n", err.Error())
				}

				conn, err := net.ListenUDP("udp", udpAddr)
				if err != nil {
					log.Printf("ListenUDP failed: %s\n", err.Error())
				}
				defer conn.Close()

				go handleUdpConnection(conn, service_data, service_name)
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

// func SendHttpDataToServer(request *string, response *string, service_name string) {
// 	decodedRequest, err := base64.StdEncoding.DecodeString(*request)
// 	if err != nil {
// 		log.Printf("Error while decoding request base64: %s", err.Error())
// 		return
// 	}

// 	requestStream := StreamData{
// 		Std:     0,
// 		DataLen: uint64(len(decodedRequest)),
// 		Data:    *request,
// 	}

// 	var stream StreamHttp

// 	if response == nil {
// 		stream = StreamHttp{
// 			Request:     &requestStream,
// 			Response:    nil,
// 			ServiceName: service_name,
// 			IsHttp:      true,
// 		}
// 	} else {
// 		decodedResponse, err := base64.StdEncoding.DecodeString(*response)
// 		if err != nil {
// 			log.Printf("Error while decoding response base64: %s", err.Error())
// 			return
// 		}

// 		responseStream := StreamData{
// 			Std:     1,
// 			DataLen: uint64(len(decodedResponse)),
// 			Data:    *response,
// 		}

// 		stream = StreamHttp{
// 			Request:     &requestStream,
// 			Response:    &responseStream,
// 			ServiceName: service_name,
// 			IsHttp:      true,
// 		}
// 	}

// 	jsonData, err := json.MarshalIndent(stream, "", "  ")
// 	if err != nil {
// 		log.Printf("Error marshaling to JSON: %s", err.Error())
// 		return
// 	}

// 	url := fmt.Sprintf("http://%s/api/new_stream", server_addr)
// 	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
// 	if err != nil {
// 		fmt.Printf("Error while sending stream to server: %s", err.Error())
// 		return
// 	}
// 	resp.Body.Close()
// }

func SendTcpDataToServer(data []StreamData, service_name string, remote_addr string) {
	if len(data) <= 0 {
		return
	}

	stream := StreamTcp{
		Stream:      data,
		ServiceName: service_name,
		RemoteAddr:  remote_addr,
		IsHttp:      false,
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

// func handleHttpConnection(conn net.Conn, service_data Service, service_name string) {
// 	defer conn.Close()

// 	var requestData bytes.Buffer
// 	buf := make([]byte, 4096)
// 	for {
// 		n, err := conn.Read(buf)
// 		if err != nil {
// 			if err == io.EOF {
// 				requestData.Write(buf[:n])
// 				break
// 			}
// 			log.Printf("Error reading request: %s", err.Error())
// 			return
// 		}

// 		requestData.Write(buf[:n])

// 		if n < 4096 {
// 			break
// 		}
// 	}
// 	log.Println(strings.Split(requestData.String(), "\n")[0])
// 	if FindBannedPatterns(requestData.String(), 0, service_name) {
// 		SendForbidden(conn)
// 		return
// 	}

// 	var newRequestData bytes.Buffer
// 	fromAddr := fmt.Sprintf("From: %s\n", []byte(strings.Split(conn.RemoteAddr().String(), ":")[0]))
// 	newRequestData.Write([]byte(fromAddr))
// 	newRequestData.Write(requestData.Bytes())
// 	encodedRequestData := base64.StdEncoding.EncodeToString(newRequestData.Bytes())

// 	serviceAddr := fmt.Sprintf("%s:%d", service_data.ServiceAddr, service_data.ServicePort)
// 	serviceConn, err := net.Dial("tcp", serviceAddr)
// 	if err != nil {
// 		log.Printf("Error connecting to service: %v", err)
// 		SendHttpDataToServer(&encodedRequestData, nil, service_name)
// 		return
// 	}
// 	defer serviceConn.Close()

// 	if _, err := serviceConn.Write(requestData.Bytes()); err != nil {
// 		log.Printf("Error sending to service: %v", err)
// 		SendHttpDataToServer(&encodedRequestData, nil, service_name)
// 		return
// 	}

// 	var responseData bytes.Buffer
// 	if _, err := io.Copy(&responseData, serviceConn); err != nil {
// 		log.Printf("Error reading response: %v", err)
// 		SendHttpDataToServer(&encodedRequestData, nil, service_name)
// 		return
// 	}
// 	if FindBannedPatterns(responseData.String(), 1, service_name) {
// 		SendForbidden(conn)
// 		return
// 	}
// 	encodedResponseData := base64.StdEncoding.EncodeToString(responseData.Bytes())
// 	SendHttpDataToServer(&encodedRequestData, &encodedResponseData, service_name)

// 	if _, err := conn.Write(responseData.Bytes()); err != nil {
// 		log.Printf("Error sending response: %v", err)
// 		return
// 	}
// }

func ReadFromTcpSocket(conn net.Conn, ch chan<- []byte) {
	for {
		var data bytes.Buffer
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					data.Write(buf[:n])
					ch <- data.Bytes()
					ch <- []byte("\xff\x7f\xc1\x05\xed\x90\x7f\xff") // means connections closed (c105ed == closed)
					return
				}
				// log.Printf("Error reading data: %s", err.Error()) // often "use of closed network connection"
				ch <- []byte("\xff\x7f\xc1\x05\xed\x90\x7f\xff")
				return
			}

			data.Write(buf[:n])

			if n < 4096 {
				break
			}
		}
		ch <- data.Bytes()
	}
}

func handleTcpConnection(conn net.Conn, service_data Service, service_name string) {
	defer conn.Close()

	serviceAddr := fmt.Sprintf("%s:%d", service_data.ServiceAddr, service_data.ServicePort)
	serviceConn, err := net.Dial("tcp", serviceAddr)
	if err != nil {
		log.Printf("Error connecting to service: %s", err.Error())
		return
	}
	defer serviceConn.Close()

	remote_addr := conn.RemoteAddr().String()
	log.Println(remote_addr)

	chanConn := make(chan []byte)
	chanServiceConn := make(chan []byte)
	go ReadFromTcpSocket(conn, chanConn)
	go ReadFromTcpSocket(serviceConn, chanServiceConn)

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	var stream []StreamData
	var tmpStream TmpStreamData
	tmpStream.Std = 0xff // means there is no previous streams

	for {
		select {
		case data := <-chanConn:
			if bytes.Equal(data, []byte("\xff\x7f\xc1\x05\xed\x90\x7f\xff")) {
				if len(tmpStream.Data.Bytes()) > 0 {
					stream = append(stream, StreamData{
						Std:     tmpStream.Std,
						DataLen: uint64(len(tmpStream.Data.Bytes())),
						Data:    base64.StdEncoding.EncodeToString(tmpStream.Data.Bytes()),
					})
				}
				SendTcpDataToServer(stream, service_name, remote_addr)
				return
			}

			if tmpStream.Std == 1 && len(tmpStream.Data.Bytes()) > 0 {
				stream = append(stream, StreamData{
					Std:     1,
					DataLen: uint64(len(tmpStream.Data.Bytes())),
					Data:    base64.StdEncoding.EncodeToString(tmpStream.Data.Bytes()),
				})
				tmpStream.Data.Reset()
				tmpStream.Std = 0
			}

			if tmpStream.Std == 0xff || tmpStream.Std == 0 {
				tmpStream.Std = 0
				tmpStream.Data.Write(data)
			}

			if FindBannedPatterns(tmpStream.Data.String(), 0, service_name) {
				SendTcpDataToServer(stream, service_name, remote_addr)
				return
			}

			if _, err := serviceConn.Write(data); err != nil {
				log.Printf("Error sending to service: %s", err.Error())
				return
			}
			timeout.Reset(5 * time.Second)
		case data := <-chanServiceConn:
			if bytes.Equal(data, []byte("\xff\x7f\xc1\x05\xed\x90\x7f\xff")) {
				if len(tmpStream.Data.Bytes()) > 0 {
					stream = append(stream, StreamData{
						Std:     tmpStream.Std,
						DataLen: uint64(len(tmpStream.Data.Bytes())),
						Data:    base64.StdEncoding.EncodeToString(tmpStream.Data.Bytes()),
					})
				}
				SendTcpDataToServer(stream, service_name, remote_addr)
				return
			}

			if tmpStream.Std == 0 && len(tmpStream.Data.Bytes()) > 0 {
				stream = append(stream, StreamData{
					Std:     0,
					DataLen: uint64(len(tmpStream.Data.Bytes())),
					Data:    base64.StdEncoding.EncodeToString(tmpStream.Data.Bytes()),
				})
				tmpStream.Data.Reset()
				tmpStream.Std = 1
			}

			if tmpStream.Std == 0xff || tmpStream.Std == 1 {
				tmpStream.Std = 1
				tmpStream.Data.Write(data)
			}

			if FindBannedPatterns(tmpStream.Data.String(), 1, service_name) {
				SendTcpDataToServer(stream, service_name, remote_addr)
				return
			}

			if _, err := conn.Write(data); err != nil {
				log.Printf("Error sending to user: %s", err.Error())
				return
			}
			timeout.Reset(5 * time.Second)
		case <-timeout.C:
			SendTcpDataToServer(stream, service_name, remote_addr)
			return
		}
	}
}

func handleUdpConnection(conn *net.UDPConn, service_data Service, service_name string) {

}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <web_app_ip> <web_app_port>\n", os.Args[0])
		return
	}

	server_addr = fmt.Sprintf("%s:%s", os.Args[1], os.Args[2])

	StartPseudoProxy()
}
