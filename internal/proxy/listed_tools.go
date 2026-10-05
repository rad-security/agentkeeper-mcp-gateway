package proxy

// ListedTools returns a read-only snapshot of the manifest cache for tool
// definition reporting: per upstream, the tools as it advertised them. It
// never starts or lists an upstream. An upstream whose consecutive listings
// were empty, which the cache treats as an intentional full removal (see
// setCachedTools), maps to an empty list; an upstream without a known list is
// absent. Callers must not modify the returned tools.
func (p *Proxy) ListedTools() map[string][]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	listed := make(map[string][]interface{}, len(p.toolCache)+len(p.emptyToolLists))
	for name, tools := range p.toolCache {
		listed[name] = cloneTools(tools)
	}
	for name, empties := range p.emptyToolLists {
		if _, cached := listed[name]; !cached && empties >= 2 {
			listed[name] = []interface{}{}
		}
	}
	return listed
}
