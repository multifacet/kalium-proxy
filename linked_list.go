package main

const (
	FALSE      int = 0
	TRUE       int = 1
	OK         int = 2
	ERROR      int = -1
	MEMORYFAIL int = -2
)

type ListNode struct {
	data *Node
	prev *ListNode
	next *ListNode
}

type Node struct {
	id         int
	ctr        int
	loop_cnt   int
	next_cnt   int
	successors [20]*ListNode
}

type List ListNode
type node_t Node

func ListInit() *ListNode {
	var l ListNode
	l.next = &l
	l.prev = &l
	return &l
}

func (l *ListNode) Empty() bool {
	if l.next == l && l.prev == l {
		return true
	}
	return false
}

func (l *ListNode) Length() int {
	count := 0
	p := l.next
	for p != l {
		count += 1
		p = p.next
	}
	return count
}

func (l *ListNode) GetPtr(pos int) *ListNode {
	p := l
	if pos < 0 || pos > l.Length() {
		return nil
	}
	for i := 1; i <= pos; i++ {
		p = p.next
	}

	return p
}

func (l *ListNode) GetElement(pos int) *Node {
	i := 1
	p := l.next
	if pos < 0 || pos > l.Length() {
		return nil
	}

	for (p != l) && (i != pos) {
		p = p.next
		i += 1
	}
	if p == l || i > pos {
		return nil
	}

	return p.data
}

func (l *ListNode) GetIdx(pnode *ListNode) int {
	idx := 0
	p := l
	if l == nil {
		return ERROR
	}
	for p != pnode {
		p = p.next
		idx += 1
	}
	if p == l {
		return ERROR
	}
	return idx
}

func (l *ListNode) Insert(pos int, node *Node) int {
	if (pos < 1) || (pos > l.Length()+1) {
		return ERROR
	}

	p := l.GetPtr(pos - 1)
	if p == nil {
		return ERROR
	}
	var tnode ListNode
	tnode.data = node
	tnode.prev = p
	tnode.next = p.next
	p.next.prev = &tnode
	p.next = &tnode
	return OK
}

func (l *ListNode) Append(node *Node) int {
	p := l.prev
	var tnode ListNode

	tnode.data = node
	p.next = &tnode
	tnode.prev = p
	tnode.next = l
	l.prev = &tnode
	return OK
}

func (l *ListNode) Remove(pos int) int {
	if (pos < 1) || (pos > l.Length()+1) {
		return ERROR
	}

	p := l.GetPtr(pos)
	p.prev.next = p.next
	p.next.prev = p.prev
	return OK
}

func SwapNode(low, high *ListNode) {
	var tmp *ListNode
	tmp = nil
	if low.next == high {
		low.prev.next = high
		high.prev = low.prev
		low.prev = high
		low.next = high.next

		high.next.prev = low
		high.next = low

		tmp = high
		high = low
		low = tmp
	} else {
		low.prev.next = high
		low.next.prev = high

		high.prev.next = low
		high.next.prev = low

		tmp = low.prev
		low.prev = high.prev
		high.prev = tmp

		tmp = low.next
		low.next = high.next
		high.next = tmp

		tmp = high
		high = low
		low = tmp
	}
}
