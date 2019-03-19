package details

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsIP(t *testing.T) {
	ips := []string{
		"192.168.0.1",
		"192.168.0.0",
		"172.168.0.1",
		"172.168.0.0",
		"1.0.0.1",
		"8.8.8.8",
		"8.8.8.0",
	}
	domains := []string{
		"google.com",
		"photos.google.com",
		"dashboard.cloudflare.com",
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.r.s.t.u.v.x.y.z.com",
	}

	badDomains := []string{
		"/:].domain.com",
		"domain,com",
		"--domain.com",
		"domaincom",
		"domain--com",
		"+domain-com",
		"domain.com+",
	}

	for _, ip := range ips {
		assert.True(t, isIPv4(ip), "Should be true: ", ip)
	}

	for _, d := range domains {
		assert.True(t, isDomain(d), "Should be true: ", d)
	}

	for _, d := range badDomains {
		assert.False(t, isDomain(d), "Should be false: ", d)
	}

}
