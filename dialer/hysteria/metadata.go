package hysteria

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	auth            string
	congestionType  string
	bandwidthTx     uint64
	bandwidthRx     uint64
	fastOpen        bool
	direct          bool
	keepAlivePeriod time.Duration
	maxIdleTimeout  time.Duration
}

func (d *hysteriaDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keyAuth           = "auth"
		keyCongestion     = "congestion"
		keyBandwidthTx    = "bandwidth.tx"
		keyBandwidthRx    = "bandwidth.rx"
		keyFastOpen       = "fastOpen"
		keyDirect         = "direct"
		keyKeepAlive      = "keepAlive"
		keyTTL            = "ttl"
		keyMaxIdleTimeout = "maxIdleTimeout"
	)

	d.md.auth = mdutil.GetString(md, keyAuth)
	d.md.congestionType = mdutil.GetString(md, keyCongestion)
	if d.md.congestionType == "" {
		d.md.congestionType = "bbr"
	}
	if v := mdutil.GetInt(md, keyBandwidthTx); v > 0 {
		d.md.bandwidthTx = uint64(v)
	}
	if v := mdutil.GetInt(md, keyBandwidthRx); v > 0 {
		d.md.bandwidthRx = uint64(v)
	}
	d.md.fastOpen = mdutil.GetBool(md, keyFastOpen)
	d.md.direct = mdutil.GetBool(md, keyDirect)

	if md == nil || !md.IsExists(keyKeepAlive) || mdutil.GetBool(md, keyKeepAlive) {
		d.md.keepAlivePeriod = mdutil.GetDuration(md, keyTTL)
		if d.md.keepAlivePeriod <= 0 {
			d.md.keepAlivePeriod = 10 * time.Second
		}
	}
	d.md.maxIdleTimeout = mdutil.GetDuration(md, keyMaxIdleTimeout)

	if d.md.maxIdleTimeout <= 0 {
		d.md.maxIdleTimeout = 30 * time.Second
	}

	return
}
