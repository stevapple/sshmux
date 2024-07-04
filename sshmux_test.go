package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

func mustRemoveAll(path string) {
	err := os.RemoveAll(path)
	if err != nil {
		log.Fatal(err)
	}
}

func mustGenerateKey(path string, type_ string) {
	mustRemoveAll(path)

	err := exec.Command("ssh-keygen", "-t", type_, "-f", path, "-N", "").Run()
	if err != nil {
		log.Fatal(err)
	}
}

var examplePrivate string

func sshAPIHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Cannot read body", http.StatusBadRequest)
		return
	}
	var dat map[string]interface{}
	if err := json.Unmarshal(body, &dat); err != nil {
		http.Error(w, "Not JSON", http.StatusBadRequest)
		return
	}

	type Response struct {
		Status     string `json:"status"`
		Address    string `json:"address"`
		PrivateKey string `json:"private_key"`
		Cert       string `json:"cert"`
		Id         int    `json:"vmid"`
	}
	var res Response
	res.Status = "ok"
	res.Address = "localhost:2333"
	res.Id = 1141919
	res.Cert = ""
	res.PrivateKey = examplePrivate
	jsonRes, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "Cannot encode JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonRes)
}

func initHttp() {
	http.HandleFunc("/ssh", sshAPIHandler)

	if err := http.ListenAndServe("127.0.0.1:5000", nil); err != nil {
		log.Fatal(err)
	}
}

func initEnv() {
	// Create /etc/sshmux/ssh_host_*_key
	err := os.MkdirAll("/tmp/sshmux", 0o755)
	if err != nil {
		log.Fatal(err)
	}
	mustGenerateKey("/tmp/sshmux/ssh_host_rsa_key", "rsa")
	mustGenerateKey("/tmp/sshmux/ssh_host_ecdsa_key", "ecdsa")
	mustGenerateKey("/tmp/sshmux/ssh_host_ed25519_key", "ed25519")

	mustGenerateKey("/tmp/sshmux/example_rsa", "rsa")
	examplePrivateBytes, err := os.ReadFile("/tmp/sshmux/example_rsa")
	if err != nil {
		log.Fatal(err)
	}
	examplePrivate = string(examplePrivateBytes)

	// Setup API Server
	go initHttp()
}

func startOnetimeSSHDServer() {
	err := exec.Command("/usr/bin/sshd", "-h", "/tmp/sshmux/ssh_host_ed25519_key", "-p", "2333", "-d", "-o", "AuthorizedKeysFile=/tmp/sshmux/example_rsa.pub", "-o", "StrictModes=no").Run()
	if err != nil {
		log.Println("sshd: ", err)
	}
}

func TestSSHClientConnection(t *testing.T) {
	initEnv()
	go mainInside("./config.example.json")

	// Sanity check
	go startOnetimeSSHDServer()
	time.Sleep(2 * time.Second)
	err := exec.Command("ssh", "-p", "2333", "-o", "StrictHostKeyChecking=no", "-o", "ControlMaster=no", "-i", "/tmp/sshmux/example_rsa", "-o", "IdentityAgent=no", "localhost", "uname").Run()
	if err != nil {
		log.Fatal("ssh: ", err)
	}

	time.Sleep(2 * time.Second)
	go startOnetimeSSHDServer()
	time.Sleep(2 * time.Second)
	err = exec.Command("ssh", "-p", "8022", "-o", "StrictHostKeyChecking=no", "-o", "ControlMaster=no", "-i", "/tmp/sshmux/example_rsa", "-o", "IdentityAgent=no", "localhost", "uname").Run()
	if err != nil {
		log.Fatal("ssh2: ", err)
	}
}
