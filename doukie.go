/*
 * multi platform, one binary, automated file transfer util by Golang.
 *
 * @author    yasutakatou
 * @copyright 2020 yasutakatou
 * @license   3-clause BSD License
 */
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	crt "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	qrcodeTerminal "github.com/Baozisoftware/qrcode-terminal-go"
	"github.com/nsf/termbox-go"
)

type Dialer struct {
	laddrIP string
	err     error
	dialer  *net.Dialer
}

type Data struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type responseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type hashTable struct {
	Filename    string `json:"Filename"`
	Hash        string `json:"Hash"`
	contentType string `json:"contentType"`
}

var (
	Hashs      = []hashTable{}
	rs1Letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	Token      string
	HTTPS      bool
	dataDir    string
	notDelete  bool
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	err := termbox.Init()
	if err != nil {
		panic(err)
	}
	defer termbox.Close()
	termbox.Flush()

	_autoSync := flag.String("auto", "", "[-auto=auto sync mode. encrypt password. (*important* You must use on trustly local network.)]")
	_autoPort := flag.String("autoPort", "9999", "[-port=port number for auto sync]")
	_autoDst := flag.String("autoDst", "", "[-autoDst=auto sync client. decrypt password.]")
	_dst := flag.String("dst", "", "[-dst=destination mode on and access url.]")
	_wait := flag.Int("wait", 10, "[-wait=sync cycle on destination mode]")
	_Dir := flag.String("dir", "data", "[-data=sync directory]")
	_Debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_https := flag.Bool("https", false, "[-https=https mode (true is enable)]")
	_token := flag.String("token", "", "[-token=authentication token (if this value is null, is set random)]")
	_port := flag.String("port", "8080", "[-port=port number]")
	_cert := flag.String("cert", "localhost.pem", "[-cert=ssl_certificate file path (if you don't use https, haven't to use this option)]")
	_key := flag.String("key", "localhost-key.pem", "[-key=ssl_certificate_key file path (if you don't use https, haven't to use this option)]")
	_notDelete := flag.Bool("notDelete", false, "[-notDelete=not delete mode (true is enable)]")

	flag.Parse()

	OSDIR := ""
	if runtime.GOOS == "linux" {
		OSDIR = "/"
	} else {
		OSDIR = "\\"
	}
	prevDir, _ := filepath.Abs(".")
	dataDir = prevDir + OSDIR + string(*_Dir) + OSDIR

	if *_Debug == true {
		fmt.Println("sync target: ", dataDir)
	}

	listUpFiles()

	HTTPS = bool(*_https)
	Token = string(*_token)
	notDelete = bool(*_notDelete)

	if Token == "" {
		Token = RandStr(8)
	}

	if *_Debug == true {
		fmt.Println(" - - - options - - - ")
		fmt.Println("auto: ", *_autoSync)
		fmt.Println("autoPort: ", *_autoPort)
		fmt.Println("autoDst: ", *_autoDst)
		fmt.Println("dst: ", *_dst)
		fmt.Println("wait: ", *_wait)
		fmt.Println("dir: ", *_Dir)
		fmt.Println("debug: ", *_Debug)
		fmt.Println("https: ", *_https)
		fmt.Println("token: ", Token)
		fmt.Println("port: ", *_port)
		fmt.Println("cert: ", *_cert)
		fmt.Println("key: ", *_key)
		fmt.Println("notDelete: ", notDelete)
		fmt.Println(" - - - - - - - - - ")
	}

	if len(*_autoDst) > 0 {
		clientAutoSync(string(*_autoDst), *_autoPort, *_wait)
	} else if len(*_dst) > 0 {
		startClient(*_dst+":"+*_port, *_wait)
	} else {
		serverAutoSync(*_autoSync, *_autoPort, *_port, *_wait)

		go func() {
			StartAPI(*_Dir, *_port, *_cert, *_key)
		}()

		fmt.Println("access token: ", Token)
		fmt.Printf("Server listening on port %s.\n", *_port)
		startServer(*_port)
	}

	os.Exit(0)
}

func serverAutoSync(server, autoport, port string, wait int) {
	if len(server) > 0 {
		fmt.Println(" - - Server AUTO SYNC! - - ")
		go func() {
			iface, ipadress, err := getIFandIP()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			conn, err := DialFromInterface(iface).Dial("udp", "224.0.0.1:"+autoport)
			//conn, err := DialFromInterface(iface).Dial("udp", ipadress + ":" + port)
			if err != nil {
				fmt.Println(err)
			}
			defer conn.Close()

			for {
				pingData, err := encrypt(ipadress+":"+port+":"+Token, []byte(addSpace(string(server))))
				if err != nil {
					fmt.Println("error: ", err)
					os.Exit(1)
				}
				conn.Write([]byte(pingData))
				fmt.Println(" ping -> ", ipadress+":"+port+":"+Token)
				time.Sleep(time.Duration(wait) * time.Second)
			}
		}()
	}
}

func clientAutoSync(dst, port string, wait int) {
	fmt.Println(" - - Client AUTO SYNC! - - ")
	iface, _, err := getIFandIP()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	nwiface, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println("cast port init fail.")
		panic(err)
	}

	fmt.Println("Listen tick server at 224.0.0.1:" + port)
	address, err := net.ResolveUDPAddr("udp", "224.0.0.1:"+port)
	if err != nil {
		fmt.Println("cast port init fail.")
		panic(err)
	}

	termbox.SetInputMode(termbox.InputEsc)

	go func() {
		for {
			switch ev := termbox.PollEvent(); ev.Type {
			case termbox.EventKey:
				switch ev.Key {
				case 27: //Escape
					termbox.Flush()
					os.Exit(0)
				default:
				}
			}
		}
	}()

	listener, err := net.ListenMulticastUDP("udp", nwiface, address)
	//defer listener.Close()
	buffer := make([]byte, 1500)
	for {
		length, _, err := listener.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("cast packet error.")
			fmt.Println(err)
		}
		decodes, err := decrypt(string(buffer[:length]), []byte(addSpace(dst)))
		if err == nil {
			params := strings.Split(decodes, ":")
			if len(params) == 3 {
				fmt.Println(" pong <- ", decodes)
				Token = params[2]
				startClient(params[0]+":"+params[1], wait)
				break
			}
		}
	}
}

func _error(_err error) {
	if _err != nil {
		panic(_err)
	}
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func getList(endpoint string) (string, string) {
	var body []byte
	var err error

	fmt.Println("request url: ", endpoint + "/" + Token + "/list")
	req, _ := http.NewRequest("GET", endpoint+"/"+Token+"/list", nil)

	if HTTPS == true {
		http.DefaultClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}

		client := &http.Client{
			Transport: http.DefaultClient.Transport,
		}
		resp, _ := client.Do(req)
		defer resp.Body.Close()

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return "Error", "not send rest api " + endpoint
		}
	} else {
		client := new(http.Client)
		resp, _ := client.Do(req)
		defer resp.Body.Close()

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return "Error", "not send rest api " + endpoint
		}
	}

	var result Data
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("logger Unmarshal error: ", err)
		return "Error", "not send rest api " + endpoint
	}

	return result.Status, result.Message
}

func DownloadFile(urls, filename string) error {
	if Exists(dataDir) == false {
		if err := os.MkdirAll(dataDir, 0777); err != nil {
			fmt.Println(err)
			return err
		}
	}

	resp, err := http.Get(urls)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dataDir + filename)
	if err != nil {
		return err
	}
	defer out.Close()

	strs := StreamToString(resp.Body)

	sDec, err := base64.StdEncoding.DecodeString(strs)
	if err != nil {
		fmt.Printf("Error decoding string: %s ", err.Error())
		return err
	}

	out.Write(sDec)
	return nil
}

func StreamToString(stream io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.String()
}

func destMode(dst string, wait int) {
	if HTTPS == true {
		dst = "https://" + dst
	} else {
		dst = "http://" + dst
	}

	for {
		Status, Message := getList(dst)
		if Status == "Success" {
			doDownload(Message, dst)
		}
		time.Sleep(time.Duration(wait) * time.Second)
	}
}

func doDownload(Message, dst string) {
	var files []string

	files = nil
	stra := strings.Split(Message, ",")
	for i := 0; i < len(stra); i++ {
		if len(stra[i]) > 1 {
			strb := strings.Split(stra[i], ":")
			if []byte(strb[0])[0] == 32 {
				strb[0] = strb[0][1:]
			}
			files = append(files, strb[0])

			if Exists(dataDir+strb[0]) == false {
				fmt.Println("not exsits download!", dst+"/"+Token+"/download/"+strb[0])
				DownloadFile(dst+"/"+Token+"/download/"+strb[0], strb[0])
			} else if strings.Index(strb[1], calcHash(dataDir+strb[0])) == -1 {
				fmt.Println("hash differ download!", dst+"/"+Token+"/download/"+strb[0])
				DownloadFile(dst+"/"+Token+"/download/"+strb[0], strb[0])
			} else {
				fmt.Println("same or exists: ", strb[0])
			}
		}
	}
	if notDelete == false {
		dstFileRemove(files)
	}
}

func dstFileRemove(lists []string) {
	listUpFiles()

	for i := 0; i < len(Hashs); i++ {
		fFlag := false
		for r := 0; r < len(lists); r++ {
			if Hashs[i].Filename == lists[r] {
				fFlag = true
			}
		}
		if fFlag == false && notDelete == false {
			fmt.Println("source not exists, remove: ", dataDir+Hashs[i].Filename)
			if err := os.Remove(dataDir + Hashs[i].Filename); err != nil {
				fmt.Println(err)
			}
		}
	}
}

func startClient(dst string, wait int) {
	termbox.SetInputMode(termbox.InputEsc)

	go func() {
		destMode(dst, wait)
	}()

	for {
		switch ev := termbox.PollEvent(); ev.Type {
		case termbox.EventKey:
			switch ev.Key {
			case 27: //Escape
				termbox.Flush()
				return
			default:
			}
		}
	}
}

func listUpFiles() {
	Hashs = nil

	files := listFile(dataDir)
	for i := 0; i < len(files); i++ {
		mime, err := GetFileContentType(dataDir + files[i])
		if err == nil {
			Hashs = append(Hashs, hashTable{Filename: files[i], Hash: calcHash(dataDir + files[i]), contentType: mime})
		}
	}
}

func GetFileContentType(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Only the first 512 bytes are used to sniff the content type.
	buffer := make([]byte, 512)

	_, err = f.Read(buffer)
	if err != nil {
		return "", err
	}

	// Use the net/http package's handy DectectContentType function. Always returns a valid
	// content-type by returning "application/octet-stream" if no others seemed to match.
	contentType := http.DetectContentType(buffer)

	return contentType, nil
}

func StartAPI(dir, port, cert, key string) {
	http.HandleFunc("/"+Token+"/list", listHandler)

	http.HandleFunc("/"+Token+"/download/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("download!: " + dataDir + r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
		downloadHandler(w, r, dataDir+r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
	})

	if HTTPS == true {
		err := http.ListenAndServeTLS(":"+port, cert, key, nil)
		if err != nil {
			log.Fatal("ListenAndServeTLS: ", err)
		}
	} else {
		err := http.ListenAndServe(":"+port, nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request, filename string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Content-Type", "application/json")

	// Open file on disk.
	f, _ := os.Open(filename)

	// Read entire JPG into byte slice.
	reader := bufio.NewReader(f)
	content, _ := ioutil.ReadAll(reader)

	// Encode as base64.
	encoded := base64.StdEncoding.EncodeToString(content)

	// Print encoded data to console.
	// ... The base64 image can be used as a data URI in a browser.
	w.Write([]byte(encoded))
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Content-Type", "application/json")

	listUpFiles()

	lists := ""

	for i := 0; i < len(Hashs); i++ {
		lists = lists + Hashs[i].Filename + ":" + Hashs[i].Hash + ":" + Hashs[i].contentType + ", "
	}

	data := &responseData{Status: "Success", Message: lists}
	outputJson, err := json.Marshal(data)
	if err != nil {
		fmt.Println("%s")
		return
	}

	w.Write(outputJson)
}

func JsonResponseToByte(status, message string) []byte {
	data := &responseData{Status: status, Message: message}
	outputJson, err := json.Marshal(data)
	if err != nil {
		return []byte(fmt.Sprintf("%s", err))
	}
	return []byte(outputJson)
}

func listFile(path string) []string {
	var lists []string

	files, _ := ioutil.ReadDir(path)
	for _, f := range files {
		lists = append(lists, f.Name())
	}
	return lists
}

func startServer(port string) {
	termbox.SetInputMode(termbox.InputEsc)

	for {

		switch ev := termbox.PollEvent(); ev.Type {
		case termbox.EventKey:
			switch ev.Key {
			case 13, 32: //Enter, Space
				printQR(port)
			case 27: //Escape
				termbox.Flush()
				return
			default:
			}
		}
	}
}

func printQR(port string) {
	_, ip, err := getIFandIP()
	if err != nil {
		fmt.Println(err)
	} else {
		termbox.Flush()
		fmt.Println("source ip: ", ip, " port: ", port)
		obj := qrcodeTerminal.New()
		URL := ""
		if HTTPS == true {
			URL = "https://" + ip + ":" + port + "/" + Token
		} else {
			URL = "http://" + ip + ":" + port + "/" + Token
		}
		obj.Get(URL).Print()
	}
}

func RandStr(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = rs1Letters[rand.Intn(len(rs1Letters))]
	}
	return string(b)
}

func calcHash(filename string) string {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

func DialFromInterface(ifaceName string) *Dialer {
	d := &Dialer{}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		d.err = err
		return d
	}

	addres, err := iface.Addrs()
	if err != nil {
		d.err = err
		return d
	}

	var targetIP string
	for _, addr := range addres {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			d.err = err
			return d
		}
		if ip.IsUnspecified() {
			continue
		}
		if ip.To4().Equal(ip) {
			targetIP = ip.String()
		}
	}
	if targetIP == "" {
		d.err = fmt.Errorf("no ipv4 found for interface")
		return d
	}
	d.laddrIP = targetIP
	return d
}

func (d *Dialer) lookupAddr(network, addr string) (net.Addr, error) {
	if d.err != nil {
		return nil, d.err
	}

	if d.dialer == nil {
		d.dialer = &net.Dialer{}
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		addr, err := net.ResolveTCPAddr(network, d.laddrIP+":0")
		return addr, err
	case "udp", "udp4", "udp6":
		addr, err := net.ResolveUDPAddr(network, d.laddrIP+":0")
		return addr, err
	default:
		return nil, fmt.Errorf("unkown network")
	}
}

func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	laddr, err := d.lookupAddr(network, addr)
	if err != nil {
		return nil, err
	}
	d.dialer.LocalAddr = laddr
	return d.dialer.Dial(network, addr)
}

func (d *Dialer) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	laddr, err := d.lookupAddr(network, addr)
	if err != nil {
		return nil, err
	}
	d.dialer.Timeout = timeout
	d.dialer.LocalAddr = laddr
	return d.dialer.Dial(network, addr)
}

func (d *Dialer) WithDialer(dialer net.Dialer) *Dialer {
	d.dialer = &dialer
	return d
}

// FYI: https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func getIFandIP() (string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return iface.Name, ip.String(), nil
		}
	}
	return "", "", errors.New("are you connected to the network?")
}

// FYI: http://www.inanzzz.com/index.php/post/f3pe/data-encryption-and-decryption-with-a-secret-key-in-golang
// encrypt encrypts plain string with a secret key and returns encrypt string.
func encrypt(plainData string, secret []byte) (string, error) {
	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(crt.Reader, nonce); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plainData), nil)), nil
}

// decrypt decrypts encrypt string with a secret key and returns plain string.
func decrypt(encodedData string, secret []byte) (string, error) {
	encryptData, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		return "", err
	}

	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(encryptData) < nonceSize {
		return "", err
	}

	nonce, cipherText := encryptData[:nonceSize], encryptData[nonceSize:]
	plainData, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainData), nil
}

func addSpace(strs string) string {
	for i := 0; len(strs) < 16; i++ {
		strs += "0"
	}
	return strs
}
