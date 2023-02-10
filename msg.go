package main

import (
	//"crypto/ecdsa"
	//"crypto/elliptic"
	"fmt"
	//"gvisor.dev/gvisor/pkg/log"
	"strconv"
)

const (
	TYPE_NONE         byte = 0x00
	TYPE_TEST         byte = 0x01
	TYPE_POLICY       byte = 0x02
	TYPE_INIT         byte = 0x03
	TYPE_KEY_DIST     byte = 0x04
	TYPE_DISK         byte = 0x05
	TYPE_EVENT        byte = 0x06
	TYPE_USER_POLICY  byte = 0x07
	TYPE_CHECK_STATUS byte = 0x08
	TYPE_CHECK_EVENT  byte = 0x09
	TYPE_CHECK_RESP   byte = 0x10
	TYPE_INFO         byte = 0x11

	ACTION_NOOP          byte = 0x01
	ACTION_TEST          byte = 0x02
	ACTION_CTR_REQ       byte = 0x03
	ACTION_GD_RESP       byte = 0x04
	ACTION_USER          byte = 0x05
	ACTION_POLICY_ADD    byte = 0x06
	ACTION_POLICY_DEL    byte = 0x07
	ACTION_POLICY_UPDATE byte = 0x08
	ACTION_POLICY_INIT   byte = 0x09
	ACTION_KEY_DIST      byte = 0x10

	STATE_REQ_RECIVED  int = 0
	STATE_REQ_VERIFIED int = 1
	STATE_PASS         int = 2
	STATE_FAILED       int = 3

	EVENT_GET   string = "GETE"
	EVENT_SEND  string = "SEND"
	EVENT_RESP  string = "RESP"
	EVENT_END   string = "ENDE"
	EVENT_DONE  string = "DONE"
	EVENT_CHECK string = "CHCK"

	EVENT_LEN int = 4

	POLICY_TABLE_INIT   int = 0
	POLICY_TABLE_UPDATE int = 1
	POLICY_TABLE_DONE   int = 2
	POLICY_TABLE_NOOP   int = 3

	MAX_LEN_SIZE   int   = 8
	MAX_BODY_LEN   int64 = 4294967295
	MAX_POLICY_LEN int64 = 1073741824

	MSG_HDR_LEN int = 10
	MSG_SIG_LEN int = 64

	MAX_KEY_LEN int = 16
	MAX_ID_LEN  int = 16

	SHA256_DIGEST_SIZE int = 256 / 8
)

type Header struct {
	typ    byte
	action byte
	length [MAX_LEN_SIZE + 1]byte
}

type Msg struct {
	header    Header
	signature [64]byte
	body      []byte
}

type MsgStr struct {
	header    [10]byte
	signature [64]byte
	body      []byte
}

type MsgStrBuff struct {
	msg_len int
	msg_str []byte
}

type Keys struct {
	key_priv [32]byte
	key_pub  [64]byte
}

type NodeInfo struct {
	id [MAX_ID_LEN]byte
}

type Event struct {
	ename [5]byte
	res   []byte
}

type ParaStateCheck struct {
	table []byte
	key   [MAX_KEY_LEN]byte
}

type PathInfo struct {
	wd   int
	name []byte
}

func InitMsgHeader(typ, action byte, msg_len int) Header {
	var hdr Header
	hdr.typ = typ
	hdr.action = action
	s := fmt.Sprintf("%08x", msg_len)
	copy(hdr.length[:], s)

	return hdr
}

func HeaderToStr(h Header) []byte {
	var s []byte
	s = append(s, h.typ)
	s = append(s, h.action)
	s = append(s, h.length[:MAX_LEN_SIZE]...)
	return s
}

func StrToHeader(s []byte) Header {
	var h Header
	h.typ = s[0]
	h.action = s[1]
	copy(h.length[:], s[2:10])
	return h
}

func KeysToString(k Keys) []byte {
	var s []byte
	s = append(s, k.key_priv[:]...)
	s = append(s, k.key_pub[:]...)
	s = append(s, []byte{0}...)
	return s
}

func StringToKeys(s []byte) Keys {
	var k Keys
	copy(k.key_priv[:], s[:32])
	copy(k.key_pub[:], s[32:64])
	return k
}

func PrintHex(s []byte) {
	for i := 0; i < len(s); i++ {
		fmt.Printf("%02x", s[i])
	}
	fmt.Printf("\n")
}

func PrintHexLen(s []byte, length int) {
	for i := 0; i < length; i++ {
		fmt.Printf("%02x", s[i])
	}
}

func MsgInit(guard_id []byte) []byte {
	h := InitMsgHeader(TYPE_INIT, ACTION_TEST, len(guard_id))
	t_hdstr := HeaderToStr(h)
	var s []byte
	s = append(s, t_hdstr[:]...)
	s = append(s, guard_id[:]...)
	return s
}

func MsgBasic(typ, action byte, msg_body []byte) []byte {
	//TODO: Using the signature length here, should it be hash?
	var hash [MSG_SIG_LEN]byte
	var res []byte
	h := InitMsgHeader(typ, action, len(msg_body))
	t_hdr_str := HeaderToStr(h)
	res = append(res, t_hdr_str[:]...)
	res = append(res, msg_body[:]...)
	res = append(res, hash[:]...)
	//log.Infof("[Guard] Sending message with data: %v", res)
	return res
}

func MsgParser(msg_str []byte) Msg {
	var msg Msg
	msg.header = StrToHeader(msg_str[:MSG_HDR_LEN])
	s := string(msg.header.length[:MAX_LEN_SIZE])
	l, err := strconv.ParseInt(s, 16, 32)
	if err != nil {
		//log.Infof("[Guard] Error parsing message header length")
	}
	//log.Infof("[Guard] Message length is %d, slice length is %d", l, len(msg_str))
	msg.body = append(msg.body, msg_str[MSG_HDR_LEN:MSG_HDR_LEN+int(l)]...)
	if len(msg_str) >= MSG_HDR_LEN+int(l)+MSG_SIG_LEN {
		copy(msg.signature[:], msg_str[MSG_HDR_LEN+int(l):MSG_HDR_LEN+int(l)+MSG_SIG_LEN])
	}
	return msg
}
