package modules

import (
	"fmt"
	"sort"
	"strings"
)

type Module interface {
	Name() string
	Description() string
	Run(args []string) ([]byte, error)
}

type Registry struct {
	modules map[string]Module
}

func NewRegistry() *Registry {
	r := &Registry{modules: make(map[string]Module)}
	r.Register(&SysInfo{})
	r.Register(&PortScan{})
	r.Register(&ProcessList{})
	r.Register(&NetStat{})
	r.Register(&EnvDump{})
	r.Register(&Screenshot{})
	r.Register(&Persist{})
	r.Register(&HashDump{})
	r.Register(NewSQLiPayloadGenerator())
	return r
}

func (r *Registry) Register(m Module) {
	r.modules[m.Name()] = m
}

func (r *Registry) Get(name string) Module {
	return r.modules[name]
}

func (r *Registry) List() []Module {
	var list []Module
	for _, m := range r.modules {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Name() < list[j].Name()
	})
	return list
}

func (r *Registry) Execute(name string, args []string) ([]byte, error) {
	m := r.Get(name)
	if m == nil {
		return nil, fmt.Errorf("module not found: %s", name)
	}
	return m.Run(args)
}

func (r *Registry) FormatList() string {
	var sb strings.Builder
	for _, m := range r.List() {
		sb.WriteString(fmt.Sprintf("  %-14s %s\n", m.Name(), m.Description()))
	}
	return sb.String()
}
