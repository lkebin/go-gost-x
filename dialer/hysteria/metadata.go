package hysteria

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	auth             string
	congestionType   string
	bandwidthTx      uint64
	bandwidthRx      uint64
	fastOpen         bool
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	maxIdleTimeout   time.Duration
}

func (d *hysteriaDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keyAuth             = "auth"
		keyCongestion       = "congestion"
		keyBandwidthTx      = "bandwidth.tx"
		keyBandwidthRx      = "bandwidth.rx"
		keyFastOpen         = "fastOpen"
		keyKeepAlive        = "keepAlive"
		keyTTL              = "ttl"
		keyHandshakeTimeout = "handshakeTimeout"
		keyMaxIdleTimeout   = "maxIdleTimeout"
	)

	d.md.auth = mdutil.GetString(md, keyAuth)
	d.md.congestionType = mdutil.GetString(md, keyCongestion)
	if d.md.congestionType == "" {
		d.md.congestionType = "bbr"
	}
	d.md.bandwidthTx = uint64(mdutil.GetInt(md, keyBandwidthTx))
	d.md.bandwidthRx = uint64(mdutil.GetInt(md, keyBandwidthRx))
	d.md.fastOpen = mdutil.GetBool(md, keyFastOpen)

	if mdutil.GetBool(md, keyKeepAlive) {
		d.md.keepAlivePeriod = mdutil.GetDuration(md, keyTTL)
		if d.md.keepAlivePeriod <= 0 {
			d.md.keepAlivePeriod = 10 * time.Second
		}
	}
	d.md.handshakeTimeout = mdutil.GetDuration(md, keyHandshakeTimeout)
	d.md.maxIdleTimeout = mdutil.GetDuration(md, keyMaxIdleTimeout)

	return
}
