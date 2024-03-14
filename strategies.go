package geneva

var Strategies = []string{
	"[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-| \\/",
	"[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{IP:ttl:replace:10},),)-| \\/",
	"[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:ack:corrupt},),)-| \\/",
	"[TCP:flags:PA]-duplicate(tamper{TCP:options-wscale:corrupt}(tamper{TCP:dataofs:replace:8},),)-| \\/",
	"[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:chksum:corrupt},),)-| \\/",
	"[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{IP:ttl:replace:8},),)-| \\/",
	"[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:ack:corrupt},),)-| \\/",
	"[TCP:flags:S]-duplicate(,tamper{TCP:load:corrupt})-| \\/",
	"[TCP:flags:PA]-duplicate(tamper{IP:len:replace:64},)-| \\/",
	"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-| \\/",
	"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:10},))-| \\/",
	"[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-| \\/",
	"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:corrupt},))-| \\/",
	"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},))-| \\/",
	"[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-| \\/",
	"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},))-| \\/",
	"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FREACN}(tamper{IP:ttl:replace:10},))-| \\/",
	"[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-| \\/",
	"[TCP:flags:PA]-fragment{tcp:8:False}-| [TCP:flags:A]-tamper{TCP:seq:corrupt}-| \\/",
	"[TCP:flags:PA]-fragment{tcp:8:True}(,fragment{tcp:4:True})-| \\/",
	"[TCP:flags:PA]-fragment{tcp:-1:True}-|  \\/",
	"[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:78},),)-|  \\/",
	"[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-| \\/",
	"[TCP:flags:PA]-tamper{TCP:options-uto:corrupt}-|  \\/",

	"[TCP:options-sackok:]-tamper{TCP:dataofs:replace:7}-| \\/",
	"[TCP:options-sack::4]-fragment{tcp:-1:False}-| \\/",
	"[TCP:options-nop:]-tamper{TCP:urgptr:corrupt}(tamper{TCP:options-eol:corrupt},)-| \\/",
	"[TCP:options-nop:]-fragment{ip:-1:True:9}(drop,)-| \\/",
	"[TCP:urgptr:0]-duplicate-| \\/",
	"[TCP:dataofs:10:3]-tamper{TCP:options-mss:replace:17484}(fragment{tcp:-1:False},)-| \\/",
	"[TCP:options-sack:]-tamper{TCP:window:corrupt}(tamper{TCP:options-eol:corrupt},)-| \\/",
	"[TCP:options-altchksum:]-duplicate(fragment{ip:-1:False},)-| \\/",
	"[TCP:options-altchksumopt:]-fragment{tcp:-1:True}-| \\/",
	"[TCP:dataofs:8]-duplicate(duplicate,)-| \\/",
	"[TCP:options-md5header:]-duplicate-| \\/",
	"[TCP:options-md5header:]-fragment{tcp:-1:False}-| [TCP:options-wscale:7]-drop-| \\/",
	"[TCP:options-uto:]-duplicate(,tamper{TCP:load:replace:y0qgai1woz})-| \\/",
	"[TCP:options-sackok::1]-tamper{TCP:window:replace:120}(tamper{TCP:ack:corrupt},)-| \\/",
	"[TCP:load:]-tamper{TCP:options-uto:corrupt}(fragment{tcp:-1:False},)-| [TCP:options-uto:]-tamper{TCP:options-mss:replace:}-| \\/",
	"[TCP:options-wscale:]-tamper{TCP:options-nop:corrupt}(tamper{TCP:options-altchksum:replace:},)-| \\/",
	"[TCP:options-sack::1]-tamper{TCP:chksum:replace:22170}-| \\/",
	"[TCP:load:]-fragment{tcp:-1:False}(tamper{TCP:urgptr:replace:29},)-| \\/",
	"[TCP:urgptr:0]-fragment{tcp:-1:False}(duplicate,tamper{TCP:options-sackok:replace:})-| \\/",
	"[TCP:options-eol:]-tamper{TCP:window:corrupt}-| \\/",
	"[TCP:options-uto:]-tamper{TCP:options-altchksum:replace:90}(duplicate(tamper{TCP:options-sack:replace:},),)-| \\/",
	"[TCP:options-altchksumopt:]-tamper{TCP:options-uto:replace:}(tamper{TCP:load:corrupt}(fragment{tcp:-1:True}(,drop),),)-| \\/",
	"[TCP:options-altchksumopt:]-fragment{tcp:-1:False}(drop,duplicate)-| \\/",
	"[TCP:options-eol:]-tamper{TCP:urgptr:corrupt}(duplicate,)-| \\/",
	"[TCP:options-sack:]-duplicate(tamper{TCP:urgptr:corrupt}(fragment{tcp:-1:False},),)-| \\/",
	"[TCP:options-nop::2]-fragment{tcp:46:True}(fragment{tcp:-1:True},)-| \\/",
	"[TCP:chksum:26741]-duplicate(tamper{TCP:options-timestamp:replace:},)-| \\/",
	"[TCP:options-uto:]-duplicate(,tamper{TCP:options-nop:replace:})-| \\/",
	"[TCP:options-altchksum:]-tamper{TCP:options-wscale:replace:248}(tamper{TCP:options-sackok:replace:},)-| \\/",
	"[TCP:options-sackok:]-duplicate(duplicate(,tamper{TCP:load:replace:GET%20/%3Fq%3Dultrasurf%20HTTP/1.1%0D%0AHost%3A%2023.88.46.143%3A4228%0D%0AUser-Agent%3A%20python-requests/2.23.0%0D%0AAccept-Encoding%3A%20gzip%2C%20deflate%0D%0AAccept%3A%20%2A/%2A%0D%0AConnection%3A%20keep-alive%0D%0A%0D%0A}),duplicate)-| \\/",
	"[TCP:options-sackok::1]-fragment{tcp:29:False:14}(tamper{TCP:options-timestamp:replace:4263716593},)-| \\/",
	"[TCP:options-altchksumopt:]-tamper{TCP:options-nop:corrupt}(duplicate,)-| \\/",

	// Can't find where these Strategies came from. They are not in the geneva paper or the geneva team's repo.
	// "[TCP:reserved:0]-fragment{tcp:-1:True}(,tamper{TCP:options-uto:replace:})-| \\/",
	// "[TCP:options-nop:]-tamper{TCP:load:replace:}(tamper{TCP:reserved:corrupt}(tamper{TCP:options-sackok:corrupt},),)-| \\/",
	// "[TCP:options-sack:]-fragment{tcp:-1:True}(,tamper{TCP:reserved:replace:1})-| \\/",
	// "[TCP:reserved:0]-duplicate(tamper{TCP:options-sackok:corrupt},)-| \\/",
}