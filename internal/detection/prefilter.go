package detection

// A pattern's regex, and a poison family's regex set, only run when a cheap
// literal prefilter admits the view. Most detection rules carry a distinctive
// literal (a command name, a known endpoint, a key prefix, an imperative verb)
// that must be present for a match. All prefilter literals across every rule
// are searched in a single Aho-Corasick pass per view, so scanning a large
// result costs one linear scan plus cheap set lookups rather than one substring
// scan per literal per rule.

// literalMatcher is an Aho-Corasick automaton compiled to a byte-indexed DFA:
// one array lookup per input byte, no per-literal rescans.
type literalMatcher struct {
	trans []int32 // numStates*256 transition table
	out   [][]int // state -> ids of literals ending at (or through) this state
	nlit  int
}

type acNode struct {
	next map[byte]int
	fail int
	out  []int
}

func newLiteralMatcher(lits []string) *literalMatcher {
	nodes := []acNode{{next: map[byte]int{}}}
	for id, lit := range lits {
		s := 0
		for i := 0; i < len(lit); i++ {
			c := lit[i]
			nx, ok := nodes[s].next[c]
			if !ok {
				nx = len(nodes)
				nodes = append(nodes, acNode{next: map[byte]int{}})
				nodes[s].next[c] = nx
			}
			s = nx
		}
		nodes[s].out = append(nodes[s].out, id)
	}
	// BFS to compute fail links and fold outputs along them.
	queue := make([]int, 0, len(nodes))
	for c := 0; c < 256; c++ {
		if nx, ok := nodes[0].next[byte(c)]; ok {
			nodes[nx].fail = 0
			queue = append(queue, nx)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for c, nx := range nodes[s].next {
			f := nodes[s].fail
			for f != 0 {
				if _, ok := nodes[f].next[c]; ok {
					break
				}
				f = nodes[f].fail
			}
			if fn, ok := nodes[f].next[c]; ok && fn != nx {
				nodes[nx].fail = fn
			} else {
				nodes[nx].fail = 0
			}
			nodes[nx].out = append(nodes[nx].out, nodes[nodes[nx].fail].out...)
			queue = append(queue, nx)
		}
	}
	// Expand to a full DFA transition table for array-speed scanning.
	m := &literalMatcher{trans: make([]int32, len(nodes)*256), out: make([][]int, len(nodes)), nlit: len(lits)}
	for s := range nodes {
		m.out[s] = nodes[s].out
	}
	for c := 0; c < 256; c++ {
		if nx, ok := nodes[0].next[byte(c)]; ok {
			m.trans[c] = int32(nx)
		}
	}
	// BFS order again so a state's transitions can reuse its fail state's.
	queue = queue[:0]
	for c := 0; c < 256; c++ {
		if nx := m.trans[c]; nx != 0 {
			queue = append(queue, int(nx))
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for c := 0; c < 256; c++ {
			if nx, ok := nodes[s].next[byte(c)]; ok {
				m.trans[s*256+c] = int32(nx)
				queue = append(queue, nx)
			} else {
				m.trans[s*256+c] = m.trans[int(nodes[s].fail)*256+c]
			}
		}
	}
	return m
}

// match returns a bool per literal id reporting whether that literal occurs in
// text, found in a single pass.
func (m *literalMatcher) match(text string) []bool {
	present := make([]bool, m.nlit)
	state := int32(0)
	for i := 0; i < len(text); i++ {
		state = m.trans[state*256+int32(text[i])]
		if out := m.out[state]; out != nil {
			for _, id := range out {
				present[id] = true
			}
		}
	}
	return present
}

// presentSet answers membership questions against one view's matched literals.
type presentSet struct {
	ids     map[string]int
	present []bool
}

func (p presentSet) has(lit string) bool {
	if id, ok := p.ids[lit]; ok {
		return p.present[id]
	}
	return false
}

func (p presentSet) anyOf(group []string) bool {
	for _, lit := range group {
		if p.has(lit) {
			return true
		}
	}
	return false
}

func (p presentSet) allGroups(groups ...[]string) bool {
	for _, g := range groups {
		if !p.anyOf(g) {
			return false
		}
	}
	return true
}

// literalIndex compiles the union of every prefilter literal into one matcher
// and assigns each a stable id.
type literalIndex struct {
	ids     map[string]int
	matcher *literalMatcher
}

func newLiteralIndex(groups ...[]string) *literalIndex {
	ids := map[string]int{}
	var lits []string
	add := func(group []string) {
		for _, lit := range group {
			if lit == "" {
				continue
			}
			if _, ok := ids[lit]; !ok {
				ids[lit] = len(lits)
				lits = append(lits, lit)
			}
		}
	}
	for _, g := range groups {
		add(g)
	}
	return &literalIndex{ids: ids, matcher: newLiteralMatcher(lits)}
}

func (li *literalIndex) presentIn(text string) presentSet {
	return presentSet{ids: li.ids, present: li.matcher.match(text)}
}
