module ddns

go 1.19


replace golang.org/x/crypto => /home/eaic/go/src/crypto

require (
	github.com/gliderlabs/ssh v0.3.4
	github.com/mattn/go-sqlite3 v1.14.14
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
)

require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	golang.org/x/sys v0.0.0-20210616094352-59db8d763f22 // indirect
)
