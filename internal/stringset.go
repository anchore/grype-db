package internal

type Set map[string]struct{}

func NewStringSet() Set {
	return make(Set)
}

func NewStringSetFromSlice(start []string) Set {
	ret := make(Set)
	for _, s := range start {
		ret.Add(s)
	}
	return ret
}

func (s Set) Add(i string) {
	s[i] = struct{}{}
}

func (s Set) Remove(i string) {
	delete(s, i)
}

func (s Set) Contains(i string) bool {
	_, ok := s[i]
	return ok
}

func (s Set) ToSlice() []string {
	ret := make([]string, len(s))
	idx := 0
	for v := range s {
		ret[idx] = v
		idx++
	}
	return ret
}
