package main

import (
	"bufio"
	"crypto/sha512"
	"database/sql"
	"encoding/base32"
	"fmt"
	"github.com/gliderlabs/ssh"
	_ "github.com/mattn/go-sqlite3"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
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
			splitUser := strings.Split(ctx.User(), ":")
			if len(splitUser) != 2 {
				return true
			}
			requestURL := url.URL{
				Scheme: "https",
				Host:   splitUser[1],
				Path:   fmt.Sprintf("/%s.keys", url.QueryEscape(splitUser[0])),
			}
			res, err := http.Get(requestURL.String())
			if err != nil {
				log.Println(fmt.Sprintf("error making http request: %s", err))
				return false
			} else {
				log.Println(fmt.Sprintf("client: status code: %d", res.StatusCode))
				sc := bufio.NewScanner(res.Body)
				for sc.Scan() {
					skey, _, _, _, err := gossh.ParseAuthorizedKey(sc.Bytes())
					if err == nil {
						if ssh.KeysEqual(key, skey) {
							return true
						}
					} else {
						log.Println(fmt.Sprintf("error parsing key: %s", err))
					}
				}
				return false
			}
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
			splitUser := strings.Split(s.User(), ":")
			var key string
			if len(splitUser) != 2 {
				key = hash(authorizedKey, secretbuf)
			} else {
				key = s.User()
				key = strings.ReplaceAll(key, "-", "-dash-")
				key = strings.ReplaceAll(key, ".", "-dot-")
				key = strings.ReplaceAll(key, ":", "-at-")
			}
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
