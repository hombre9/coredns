package acl

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics/vars"
	"github.com/coredns/coredns/plugin/pkg/rcode"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// ACL is plugin to filter (allow/deny) requests internally before being handled.
type ACL struct {
	Next plugin.Handler
	Rules []Rule
}

// ServeDNS implements the plugin.Handler interface.
func (a ACL) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	ip := net.ParseIP(state.IP())

	for _, it := range a.Rules {
		if (it.anyHost == true || it.cidr.Contains(ip)) &&
		   (it.anyType == true || it.queryType == r.Question[0].Qtype) {
			if (it.action == "allow") {
				return plugin.NextOrFailure(a.Name(), a.Next, ctx, w, r)
			} else if (it.action == "deny") {
				break
			}
		}
	}

	answer := new(dns.Msg)
	answer.SetRcode(r, dns.RcodeRefused)

	state.SizeAndDo(answer)

	vars.Report(ctx, state, vars.Dropped, rcode.ToString(dns.RcodeRefused), answer.Len(), time.Now())

	w.WriteMsg(answer)

	return 0, nil
}

// Name implements the Handler interface.
func (a ACL) Name() string { return "acl" }

// Rule describes an ACL rule.
type Rule struct {
	action string
	anyHost bool
	anyType bool
	cidr *net.IPNet
	queryType uint16
}

func newRule(args ...string) (Rule, error) {
	var rule Rule
	var err error
	var ok bool

	if len(args) == 0 {
		return rule, fmt.Errorf("no rule type specified")
	}

	rule.action = strings.ToLower(args[0])
	if rule.action != "allow" && rule.action != "deny" {
		return rule, fmt.Errorf("invalid rule type %q", rule.action)
	}

	rule.anyHost = true
	rule.anyType = true

	if len(args) > 1 && strings.ToLower(args[1]) == "type" {
		arg := strings.ToUpper(args[2])
		if rule.queryType, ok = dns.StringToType[arg]; !ok {
			return rule, fmt.Errorf("invalid type %q", args)
		}
		rule.anyType = false
		args = args[2:]
	}

	if len(args) == 3 && strings.ToLower(args[1]) == "from" {
		arg := strings.ToLower(args[2])
		if _, rule.cidr, err = net.ParseCIDR(arg); err != nil {
			return rule, fmt.Errorf("unable to parse CIDR %q", arg)
		}
		rule.anyHost = false
	}

	return rule, nil
}
