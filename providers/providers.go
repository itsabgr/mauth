package providers

import (
	"fmt"
)

var Map = make(map[string]Provider)

func Register(p Provider) {
	_, exists := Map[p.Name()]
	if exists {
		panic(fmt.Errorf("provider %q already registered", p.Name()))
	}
	Map[p.Name()] = p
}
