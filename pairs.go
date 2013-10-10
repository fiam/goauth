package oauth

import (
	"fmt"
	"sort"
	"strings"
)

type Pair struct {
	Key   string
	Value string
}

func (p *Pair) Encode() string {
	return fmt.Sprintf("%s=%s", Encode(p.Key), Encode(p.Value))
}

func (p *Pair) EncodeQuoted() string {
	return fmt.Sprintf("%s=\"%s\"", Encode(p.Key), Encode(p.Value))
}

type Params []*Pair

func (p *Params) Add(pair *Pair) {
	a := *p
	n := len(a)

	if n+1 > cap(a) {
		s := make([]*Pair, n, 2*n+1)
		copy(s, a)
		a = s
	}
	a = a[0 : n+1]
	a[n] = pair
	*p = a

}

func (p Params) Encode() string {
	values := make([]string, len(p))
	for ii, v := range p {
		values[ii] = v.Encode()
	}
	sort.Strings(values)
	return strings.Join(values, "&")
}

func NewParams(key ...string) Params {
	var p Params
	for ii := 0; ii < len(key); ii += 2 {
		p.Add(&Pair{Key: key[ii], Value: key[ii+1]})
	}
	return p
}
