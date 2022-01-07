package geneva_test

import (
	"testing"

	"github.com/getlantern/geneva"
)

var (
	examples []string = []string{
		"[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-|",
		"[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{IP:ttl:replace:10},),)-|",
		"[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:ack:corrupt},),)-|",
		"[TCP:flags:PA]-duplicate(tamper{TCP:options-wscale:corrupt}(tamper{TCP:dataofs:replace:8},),)-|",
		"[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:chksum:corrupt},),)-|",
		"[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{IP:ttl:replace:8},),)-|",
		"[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:ack:corrupt},),)-|",
		"[TCP:flags:S]-duplicate(,tamper{TCP:load:corrupt})-|",
		"[TCP:flags:PA]-duplicate(tamper{IP:len:replace:64},)-|",
		"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-|",
		"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:10},))-|",
		"[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-|",
		"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:corrupt},))-|",
		"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},))-|",
		"[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-|",
		"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},))-|",
		"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FREACN}(tamper{IP:ttl:replace:10},))-|",
		"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-|",
		"[TCP:flags:PA]-fragment{tcp:8:False}-| [TCP:flags:A]-tamper{TCP:seq:corrupt}-|",
		"[TCP:flags:PA]-fragment{tcp:8:True}(,fragment{tcp:4:True})-|",
		"[TCP:flags:PA]-fragment{tcp:-1:True}-|",
		"[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:78},),)-|",
		"[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-|",
		"[TCP:flags:PA]-tamper{TCP:options-uto:corrupt}-|",
	}
)

func TestNewStrategy(t *testing.T) {
	for _, s := range examples {
		_, err := geneva.NewStrategy(s)
		if err != nil {
			t.Errorf("failed to parse strategy: %v", err)
		}
	}
}
