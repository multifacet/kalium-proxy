package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	zmq "github.com/deepaksirone/goczmq"
	//"runtime"
	//"time"
	//"github.com/grpc/grpc-go"
	"encoding/gob"
	//specs "github.com/opencontainers/runtime-spec/specs-go"
	//"golang.org/x/sys/unix"
	//"gvisor.dev/gvisor/pkg/log"
	//"gvisor.dev/gvisor/runsc/specutils"
	//"net/http"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	ioWhitelist  int = 0
	ipWhitelist  int = 1
	urlWhitelist int = 2
)

type Guard struct {
	id int
	// IO Rate
	ior int
	// Requests rate limit
	netr int
	// No. of request
	requestNo int
	// Number of IO
	ioNo int
	// Start time
	startTime int64
	// Running time
	runningTime uint64
	// Event mapping table
	eventMap map[int64]int
	// State table
	stateTable map[string]int
	// IO whitelist
	ioWhitelist map[string]int
	// IP whitelist
	ipWhitelist map[string]int
	// URL whitelist
	urlWhitelist map[string]int
	// Policy table
	policyTable map[string]*ListNode
	// Controller IP
	ctrIP string
	// Controller Port
	ctrPort int64
	// Local Function Graph
	graph *ListNode
	// Current State
	curState *ListNode
	// Sandbox2seclambda FD
	sandboxSide int
	// Seclambda2sandbox FD
	seclambdaSide int
	// Function name
	funcName string
	// Sandbox File
	SandboxFile *os.File
	// Seclambda File
	SeclambdaFile *os.File
}

type Policy struct {
	//NAME    string
	//EVENTID []map[string]float64
	URL  []string
	IP   []string
	IOR  float64
	IO   []string
	NETR float64
	//GLOBALGRAPH map[string][]map[string]interface{}
	GRAPH map[string]interface{}
}

type KernMsg struct {
	EventName [4]byte
	//MetaData  []byte
	Url       string
	Method    string
	PeerAddr  string
	PeerPort  int
	HasBody   int
	SessionId string
	//Data      []byte
	MsgID    int64
	IsExit   bool
	FuncName string
	IsFunc   bool
}

type ReturnMsg struct {
	Allowed bool
	MsgID   int64
	Policy  []byte
}

var checkChannel = make(chan int)

/*
func get_func_name() string {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") == "" {
		return string("test0")
	}
	return os.Getenv("AWS_LAMBDA_FUNCTION_NAME")
}*/

func get_region_name() string {
	if os.Getenv("AWS_REGION") == "" {
		return "AWS_EAST"
	}
	return os.Getenv("AWS_REGION")
}

func get_inst_id() []byte {
	return []byte("sandbox-ab6a0e")
}

func split_str(s, sep string) []string {
	return strings.Split(s, sep)
}

func strip(s string, c byte) string {
	var res string
	for i := 0; i < len(s); i++ {
		if s[i] != c {
			res += string(s[i])
		}
	}
	return res
}

func get_time() int64 {
	var r syscall.Timeval
	err := syscall.Gettimeofday(&r)
	if err != nil {
		return 0
	}
	return 1000000*r.Sec + int64(r.Usec)
}

func djb2hash(func_name, event, url, action string) uint64 {
	inp := func_name + event + url + action
	var hash uint64 = 5381
	for i := 0; i < len(inp); i++ {
		hash = ((hash << 5) + hash) + uint64(inp[i])
	}
	return hash
}

func (g *Guard) get_event_id(event_hash int64) (int, bool) {
	id, present := g.eventMap[event_hash]
	return id, present
}

func New(ctrIP string, ctrPort int, sandboxSide int, seclambdaSide int, hostname string) Guard {
	var g Guard
	g.startTime = get_time()
	g.requestNo = 0
	g.ioNo = 0
	g.runningTime = 0
	g.ctrIP = ctrIP
	g.ctrPort = int64(ctrPort)
	g.eventMap = make(map[int64]int)
	g.ioWhitelist = make(map[string]int)
	g.ipWhitelist = make(map[string]int)
	g.urlWhitelist = make(map[string]int)
	g.stateTable = make(map[string]int)
	g.policyTable = make(map[string]*ListNode)
	g.sandboxSide = sandboxSide
	g.seclambdaSide = seclambdaSide

	if hostname != "" {
		n := strings.Split(hostname, "-")
		if len(n) > 2 {
			g.funcName = strings.Join(n[:len(n)-2], "-")
		} else {
			g.funcName = strings.Join(n, "-")
		}
	} else {
		g.funcName = ""
	}

	return g
}

func (g *Guard) Lookup(hash_id int, key string) bool {
	switch hash_id {
	case ioWhitelist:
		_, present := g.ioWhitelist[key]
		return present
	case ipWhitelist:
		_, present := g.ipWhitelist[key]
		return present
	case urlWhitelist:
		_, present := g.urlWhitelist[key]
		return present
	default:
		return false
	}
}

/*
func KeyInitReq(s *zmq.Sock, guard_id []byte) {
	m := MsgInit(guard_id)
	s.SendFrame(m, zmq.FlagNone)
}
*/

func keyInitHandler(msg []byte) {
	return
}

func SendToCtr(s *zmq.Channeler, typ, action byte, data []byte) {
	m := MsgBasic(typ, action, data)
	s.SendChan <- [][]byte{m}
}

func (g *Guard) PolicyInitHandler(msg []byte) {
	var f Policy
	err := json.Unmarshal(msg, &f)
	if err != nil {
		log.Println("[Guard] Error parsing json: %v", msg)
		return
	}

	g.ior = int(f.IOR)
	g.netr = int(f.NETR)

	log.Println("[Seclambda] Here 1")
	for i := 0; i < len(f.IO); i++ {
		g.ioWhitelist[f.IO[i]] = 1
	}

	for i := 0; i < len(f.IP); i++ {
		g.ipWhitelist[f.IP[i]] = 1
	}

	for i := 0; i < len(f.URL); i++ {
		g.urlWhitelist[f.URL[i]] = 1
	}

	log.Println("[Seclambda] Here 2")

	func_name := f.GRAPH["NAME"].(string)
	eventid := f.GRAPH["EVENTID"].([]interface{})
	//log.Infof("[Guard] The eventid map : %v", eventid)
	var eventid_map []map[string]int
	log.Println("[Seclambda] Here 3")
	for _, v := range eventid {
		switch vv := v.(type) {
		case map[string]interface{}:
			m := make(map[string]int)
			for i, u := range vv {
				m[i] = int(u.(float64))
			}
			eventid_map = append(eventid_map, m)
		}
	}

	log.Println("[Seclambda] Here 4")
	for _, m := range eventid_map {
		h := int64(m["h"])
		k := m["e"]
		g.eventMap[h] = k
	}
	log.Println("[Seclambda] Here 5")
	g.graph = ListInit()
	var ns_map []map[string]int
	ns := f.GRAPH["NS"].([]interface{})
	log.Println("[Seclambda] Here 5 1")
	for _, v := range ns {
		switch vv := v.(type) {
		case map[string]interface{}:
			m := make(map[string]int)
			for i, u := range vv {
				//fmt.Printf("%T %T\n", i, u)
				//fmt.Println(i, u)
				//f, _ := strconv.ParseInt(i, 10, 64)
				m[i] = int(u.(float64))
			}
			ns_map = append(ns_map, m)
		}
	}
	log.Println("[Seclambda] Here 6")
	for _, m := range ns_map {
		var tnode Node
		tnode.id = int(m["id"])
		tnode.next_cnt = 0
		tnode.loop_cnt = int(m["cnt"])
		g.graph.Append(&tnode)
	}
	log.Println("[Seclambda] Here 7")
	es := f.GRAPH["ES"].([]interface{})
	for _, v := range es {
		switch vv := v.(type) {
		case map[string]interface{}:
			var dsts []int
			var src []int
			for i, u := range vv {
				if i == "1" {
					d := u.([]interface{})
					for _, v1 := range d {
						dsts = append(dsts, int(v1.(float64)))
					}
				} else {
					src = append(src, int(u.(float64)))
				}
			}
			p_ns := g.graph.GetElement(src[0] + 1)
			for _, d := range dsts {
				if d != -1 {
					p_nd := g.graph.GetPtr(d + 1)
					p_ns.successors[p_ns.next_cnt] = p_nd
					p_ns.next_cnt = p_ns.next_cnt + 1
				} else {
					p_ns.successors[p_ns.next_cnt] = g.graph
					p_ns.next_cnt = p_ns.next_cnt + 1
				}
			}

		}
	}
	log.Println("[Seclambda] Here 7")
	g.policyTable[func_name] = g.graph
	g.curState = g.graph
	log.Println("[Seclambda] Here 8")
}

func (g *Guard) PolicyInit() {
	p := g.graph.next
	for p != g.graph {
		nptr := p.data
		nptr.ctr = nptr.loop_cnt
		p = p.next
	}
	g.curState = g.graph
}

func (g *Guard) CheckPolicy(event_id int) bool {
	fname := g.get_func_name()
	_, present := g.policyTable[fname]
	if !present {
		log.Println("[Seclambda] #1 Returning false for ev_id: %v", event_id)
		return false
	}

	p := g.curState
	if g.graph == g.curState {
		g.PolicyInit()
		g.curState = g.curState.next
		p = g.curState
	}

	nptr := p.data
	if nptr.id == event_id {
		if nptr.ctr > 0 {
			nptr.ctr = nptr.ctr - 1
			return true
		}
		log.Println("[Seclambda] #2 Returning false for ev_id: %v", event_id)
		return false
	}

	for i := 0; i < nptr.next_cnt; i++ {
		next_ptr := nptr.successors[i]
		next_d_ptr := next_ptr.data

		if (next_d_ptr.ctr > 0) && (next_d_ptr.id == event_id) {
			next_d_ptr.ctr = next_d_ptr.ctr - 1
			g.curState = next_ptr
			return true
		}
	}
	log.Println("[Seclambda] #3 Returning false for ev_id: %v", event_id)
	return false
}

func (g *Guard) handleSandbox(dec *gob.Decoder, updater *zmq.Channeler,
	sandboxExit chan int, sandboxFile *os.File, encoder *gob.Encoder) {
	//replyFile := os.NewFile(uintptr(g.seclambdaSide), "seclambdaSide")
	//encoder := gob.NewEncoder(replyFile)
	rid := get_inst_id()
	fname := g.get_func_name()

	//defer replyFile.Close()
	for {
		var msg KernMsg
		//sandboxFile.SetDeadline(time.Now().Add(2 * time.Microsecond))
		//log.Println("[Seclambda] Decoding message")
		err := dec.Decode(&msg)
		//log.Println("[Seclambda] Decoded message")
		//s := time.Now()
		//log.Printf("[Seclambda] Timestamp of receiving message with ID: %v : %v", msg.MsgID, s.UnixNano())
		//if os.IsTimeout(err) {
		//	continue
		//}

		if err != nil {
			log.Println("[Seclambda] Decode Error; ProxyDying: ", err)
			sandboxExit <- 1
			return
		}

		//ch <- msg
		//	if msg.IsExit {
		//		// Kill off this go routine if the sandbox is exiting
		//		return
		//	}
		//log.Infof("[Seclambda] Received a message from the kernel")
		//log.Infof("[Seclambda] The message struct : %v", msg)
		if msg.IsExit {
			// Kill the go routine on kernel exit message
			sandboxExit <- 1
			//log.Println("[Seclambda] Exiting the go-routine")
			return
		}

		if msg.IsFunc {
			//log.Println("[Seclambda] New function name; Ignoring")
			continue
		}

		//n := strings.Split(msg.FuncName, "-")
		//fname = strings.Join(n[:len(n)-2], "-")
		//g.requestNo += 1
		//replied := false
		/*
			if len(msg.Data) == 0 {
				//msg.RecvChan <- 0 // [TODO] Respond with appropriate error
				continue
			}*/

		event := string(msg.EventName[:])
		//log.Println("[SeclambdaMeasure] Request Number: %d, Event: %s", g.requestNo, event)
		//start := time.Now()
		if event == "CHCK" {
			SendToCtr(updater, TYPE_CHECK_STATUS, ACTION_NOOP, []byte(fname))
			//TODO: Change this to a seclambdaFD comm
			//encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID})
			//msg.RecvChan <- 1 //[TODO] Need to augment this structure
			//replied = true
			continue
		}

		//meta := string(msg.MetaData)
		meta := fmt.Sprintf("%s:%s:%s:%d:%d:%s", msg.Url, msg.Method, msg.PeerAddr, msg.PeerPort, msg.HasBody, msg.SessionId)
		out := fmt.Sprintf("%s:%s:%s:%s", fname, event, meta, string(rid))
		//log.Infof("[Seclambda] Out string: %s", out)

		//info := strings.Split(meta, ":")
		//log.Println("[Seclambda] info[0]: %v, info[1]: %v", info[0], info[1])
		//ev_hash := djb2hash(fname, event, info[0], info[1])
		//start1 := time.Now()
		//ev_id, present := g.get_event_id(int64(ev_hash))
		//log.Println("[SeclambdaMeasure] Time for event check: %s", time.Since(start1))
		//log.Println("[Seclambda] info[0]: %v, info[1]: %v ev_id: %v, present: %v, msgID: %v", info[0], info[1], ev_id, present, msg.MsgID)
		if event == "GETE" {
			// TODO: Change this to a seclambdaFD comm
			// TODO: Make this synchronous
			//log.Println("[SeclambdaMeasure] GETE: Time for Aux processing: %s", time.Since(start))
			//start1 := time.Now()

			//encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID})

			//log.Println("[SeclambdaMeasure] GETE: Time to send to sandbox: %s", time.Since(start1))
			//msg.RecvChan <- 1
			//start2 := time.Now()
			SendToCtr(updater, TYPE_CHECK_EVENT, ACTION_NOOP, []byte(out))
			log.Println("[Seclambda] Sent TYPE_CHECK_EVENT to controller")
			//log.Println("[SeclambdaMeasure] GETE: Time for async controller notif: %s", time.Since(start2))
			resp := <-checkChannel
			if resp == 1 {
				//log.Println("[GETE] Sending Allowed")
				encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID, Policy: []byte{}})
				//g.SeclambdaFile.Sync()
			} else {
				//log.Println("[GETE] Sending disallowed")
				encoder.Encode(ReturnMsg{Allowed: false, MsgID: msg.MsgID, Policy: []byte{}})
				//g.SeclambdaFile.Sync()
			}
		} else if event == "ENDE" {
			//log.Println("[SeclambdaMeasure] ENDE: Time for Aux processing: %s", time.Since(start))
			//start1 := time.Now()
			g.PolicyInit()
			//log.Println("[SeclambdaMeasure] ENDE: Time for PolicyInit: %s", time.Since(start1))
			//TODO: Change this to a seclambdaFD comm
			//start2 := time.Now()

			//encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID})
			//msg.RecvChan <- 1 // [TODO] Send an empty message to the hypercall
			//log.Println("[SeclambdaMeasure] ENDE: Time to send to sandbox: %s", time.Since(start2))
			//replied = true
			//start3 := time.Now()
			SendToCtr(updater, TYPE_EVENT, ACTION_NOOP, []byte(out))
			//log.Println("[SeclambdaMeasure] ENDE: Time for async controller notif: %s", time.Since(start3))
		} else if event == "SEND" || event == "RESP" || event == "GETE" {
			//log.Println("[SeclambdaMeasure] SEND-RESP: Time for Aux processing: %s", time.Since(start))
			//start1 := time.Now()
			//FIXME: No need for this //if present && g.CheckPolicy(ev_id) {
			//TODO: Change this to a seclambdaFD comm
			//log.Println("[SeclambdaMeasure] SEND-RESP-present: Time for Policy Check : %s", time.Since(start1))
			//start2 := time.Now()

			//encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID})

			//log.Println("[SeclambdaMeasure] SEND-RESP-present: Time to send to sandbox: %s", time.Since(start2))
			//msg.RecvChan <- 1
			//start3 := time.Now()
			//log.Println("[Seclambda] Sending event to controller")
			SendToCtr(updater, TYPE_EVENT, ACTION_NOOP, []byte(out))
			//log.Println("[SeclambdaMeasure] SEND-RESP-present: Time for async controller notif %s", time.Since(start3))
			//FIXME: Unecessary if-else } else {
			//log.Infof("[Seclambda] Event: %v not present or not allowed by policy", ev_id)
			//TODO: Change this to a seclambdaFD comm
			//log.Println("[SeclambdaMeasure] SEND-RESP-absent: Time for Policy Check (absent): %s", time.Since(start1))
			//start2 := time.Now()

			//encoder.Encode(ReturnMsg{Allowed: false, MsgID: msg.MsgID})

			//s := time.Now()
			//log.Printf("[Seclambda] Timestamp of replying to  message with ID: %v : %v", msg.MsgID, s.UnixNano())
			//log.Println("[SeclambdaMeasure] SEND-RESP-absent: Time to send to sandbox: %s", time.Since(start2))
			//msg.RecvChan <- 0
			//start3 := time.Now()
			//SendToCtr(updater, TYPE_EVENT, ACTION_NOOP, []byte(out))
			//log.Println("[SeclambdaMeasure] SEND-RESP-absent: Time for async controller notif: %s", time.Since(start3))
			//}
			//replied = true
		}

		/*
			if !replied {
				//TODO: Change) this to a seclambdaFD comm
				//log.Println("[SeclambdaMeasure] NO-Reply: Time for Aux processing: %s", time.Since(start))
				//start1 := time.Now()

				encoder.Encode(ReturnMsg{Allowed: false, MsgID: msg.MsgID})
				//log.Println("[SeclambdaMeasure] NO-Reply: Time for sandbox reply: %s", time.Since(start1))
				//msg.RecvChan <- 0 //[TODO] Invalid message!
			}
		*/

	}
}

func (g *Guard) get_func_name() string {
	return g.funcName
}

func (g *Guard) Run(wg *sync.WaitGroup) {

	g.SandboxFile = os.NewFile(uintptr(g.sandboxSide), "sandbox-fd")
	bufSandboxFile := bufio.NewReaderSize(g.SandboxFile, 60*1024*1024)
	//bufSandboxFile := g.SandboxFile
	dec := gob.NewDecoder(bufSandboxFile)

	g.SeclambdaFile = os.NewFile(uintptr(g.seclambdaSide), "seclambdaSide")
	//bufReplyFile := bufio.NewWriterSize(replyFile, 20*1024*1024)
	encoder := gob.NewEncoder(g.SeclambdaFile)

	defer g.SandboxFile.Close()

	var funcMsg KernMsg
	dec.Decode(&funcMsg)
	if funcMsg.FuncName != "" {
		log.Printf("[Seclambda] Received function name: %v", funcMsg.FuncName)
		n := strings.Split(funcMsg.FuncName, "-")
		if len(n) <= 2 {
			g.funcName = strings.Join(n, "-")
		} else {
			g.funcName = strings.Join(n[:len(n)-2], "-")
		}
		log.Printf("[Seclambda] Set function name: %v", g.funcName)
		//g.funcName = funcMsg.FuncName
	}

	id := g.get_func_name() + strconv.FormatInt(get_time(), 10)
	f, err := os.OpenFile("/mydata/seclambda_log/seclambda."+id, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.Println("[Seclambda] Started Guard with id: " + id)
	fname := g.get_func_name()
	idOpt := zmq.SockSetIdentity(id)
	log.Println("[Seclambda] Attempting to connect to %v at port: %v", g.ctrIP, g.ctrPort)

	updater := zmq.NewDealerChanneler("tcp://"+g.ctrIP+":"+strconv.FormatInt(g.ctrPort, 10), idOpt)
	//rid := get_inst_id()
	//go g.handleSandbox(updater)
	/*
		if err != nil {
			log.Infof("[ZMQ] Error attaching to Controller")
		}*/
	/*
		e := updater.Connect("tcp://127.0.0.1:5000")
		if e != nil {
			log.Infof("Error connecting to Controller")
		}*/

	log.Printf("[Seclambda] Started Guard with id: " + id)
	keyInitMsg := MsgInit([]byte(id))
	//log.Println("Sending message: %v", keyInitMsg)
	updater.SendChan <- [][]byte{keyInitMsg}

	sandboxExit := make(chan int)
	//time.Sleep(3 * time.Second)
	//go g.handleSandbox(dec, updater, sandboxExit, sandboxFile)
	/*
		if er != nil {
			log.Infof("[ZMQ] Error sending message to Controller")
		}*/ /*
		_, ero := net.Dial("tcp", "golang.org:80")
		if ero != nil {
			log.Infof("Unable to connect to Controller")
			log.Infof(ero.Error())
		}*/
	/*
		conn, err := grpc.Dial("127.0.0.1:7777", grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Infof("[GRPC] Unable to connect to localhost")
		}
		defer conn.Close()
		c := pb.NewGreeterClient(conn)
	*/
	//log.Infof("[Seclambda] Send KeyInitReq to controller " + fname)
	defer wg.Done()
	//defer replyFile.Close()

	//recv := <-updater.RecvChan
	//log.Infof("[Guard] Received: %s", string(recv[0]))

	for {
		// Receive signal from kernel
		// and break out of this loop
		select {
		case <-sandboxExit:
			//log.Println("[Seclambda] Exiting the go-routine")
			return

		case recv := <-updater.RecvChan:
			if len(recv[0]) <= 1 {
				continue
			}
			msg := MsgParser(recv[0])
			typ := msg.header.typ
			action := msg.header.action
			//msg.header.length[MAX_LEN_SIZE] = 0
			_, err := strconv.ParseInt(string(msg.header.length[:MAX_LEN_SIZE]), 16, 64)
			if err != nil {
				//log.Infof("[Seclambda] failed to parse message length: %s", string(msg.header.length[:]))
				continue
			}
			switch typ {
			case TYPE_KEY_DIST:
				keyInitHandler(msg.body)
				//log.Println("[Seclambda] Registered Keys: " + fname)
				SendToCtr(updater, TYPE_POLICY, ACTION_POLICY_INIT, []byte(fname))
			case TYPE_POLICY:
				var err error
				if action == ACTION_POLICY_ADD {
					//log.Println("[Seclambda] Before PolicyInitHandler")
					//log.Println("[Seclambda] Printing Policy: %v", string(msg.body))
					//g.PolicyInitHandler(msg.body)
					//log.Println("[Seclambda] Finish registration; get policy")
					//ctr <- 1
					err = encoder.Encode(ReturnMsg{Allowed: true, MsgID: 0, Policy: msg.body})
					g.SeclambdaFile.Sync()
				} else {
					//log.Printf("[Seclambda] Got back policy message: %v", msg)
					err = encoder.Encode(ReturnMsg{Allowed: true, MsgID: 0, Policy: []byte{}})
					g.SeclambdaFile.Sync()
				}

				if err != nil {
					log.Printf("[Seclambda] Error sending policy")
				}

				go g.handleSandbox(dec, updater, sandboxExit, g.SandboxFile, encoder)

			case TYPE_CHECK_RESP:
				// Assuming that each request is sequential
				log.Println("Received TYPE_CHECK_RESP message")
				if msg.body[0] == 0x41 {
					checkChannel <- 1
				} else {
					checkChannel <- 0
				}
			case TYPE_CHECK_STATUS:
				//log.Infof("[Seclambda] Send status to guard")
				g.runningTime = uint64(get_time() - g.startTime)
				s := strconv.FormatInt(int64(g.requestNo), 10) + string(":") + strconv.FormatUint(g.runningTime, 10)
				SendToCtr(updater, TYPE_CHECK_STATUS, ACTION_GD_RESP, []byte(s))
			case TYPE_TEST:

			//case TYPE_NONE:

			//default:

			}

		}

	}
}
