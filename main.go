package main

import (
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

func hash(bytes []byte, secret []byte) string {
	encoding := base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789")
	h := sha512.New()
	h.Write(bytes)
	h.Write(secret)
	hash := h.Sum(nil)
	return encoding.EncodeToString([]byte(hash[:]))[:36]
}

type any interface {
}
func die(err any) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	secretbuf, err := ioutil.ReadFile("/home/eaic/ddnsData/sshkey")
	die(err)
	key, err := gossh.ParseRawPrivateKey(secretbuf)
	die(err)
	signer, err := gossh.NewSignerFromKey(key)
	die(err)
	db, err := sql.Open("sqlite3", "/home/eaic/ddnsData/names.db")
	die(err)
	setIp1, err := db.Prepare("UPDATE ddns SET ip=$1 WHERE key=$2;")
	setIp2, err := db.Prepare("INSERT OR IGNORE INTO ddns (ip, key) VALUES ($1, $2);")
	die(err)
	defer db.Close()
	s := &ssh.Server{
		Addr: "134.195.121.112:22",
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			return true // allow all keys, or use ssh.KeysEqual() to compare against known keys
		},
	}
	s.AddHostKey(signer)
	s.Handle(func(s ssh.Session) {
		stderr := s.Stderr()
		banner, err := ioutil.ReadFile("./banner.txt")
		if err == nil {
			stderr.Write(banner)
		}
		authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
		host, _, err := net.SplitHostPort(s.RemoteAddr().String())
		if err == nil {
			customHost := s.RawCommand()
			if customHost == "" {
				// no custom ip
			} else {
				parsedCustomHost := net.ParseIP(customHost)
				if parsedCustomHost == nil || parsedCustomHost.To4() == nil {
					io.WriteString(stderr, fmt.Sprintf("'%s' is not a valid IPv4 address\n", customHost))
					return
				} else {
					host = customHost
				}
			}
			key := hash(authorizedKey, secretbuf)
			_, err := setIp1.Exec(host, key)
			_, err = setIp2.Exec(host, key)
			if err != nil {
				log.Println(err)
				io.WriteString(stderr, "db error\n")
				return
			}
			io.WriteString(s, fmt.Sprintf("%s.ddns.rodeo\n", key))
		} else {
			io.WriteString(stderr, fmt.Sprintf("wtf are you doing?\n"))
		}
	})
	log.Println("starting ssh server on port 22...")
	log.Fatal(s.ListenAndServe())
}
