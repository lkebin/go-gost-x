package hysteria

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	auth             string
	congestionType   string
	bandwidthTx      uint64
	bandwidthRx      uint64
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	maxIdleTimeout   time.Duration
	disableUDP       bool
	backlog          int
}

func (l *hysteriaListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keyAuth             = "auth"
		keyCongestion       = "congestion"
		keyBandwidthTx      = "bandwidth.tx"
		keyBandwidthRx      = "bandwidth.rx"
		keyKeepAlive        = "keepAlive"
		keyTTL              = "ttl"
		keyHandshakeTimeout = "handshakeTimeout"
		keyMaxIdleTimeout   = "maxIdleTimeout"
		keyDisableUDP       = "disableUDP"
		keyBacklog          = "backlog"
	)

	l.md.auth = mdutil.GetString(md, keyAuth)
	l.md.congestionType = mdutil.GetString(md, keyCongestion)
	if l.md.congestionType == "" {
		l.md.congestionType = "bbr"
	}
	l.md.bandwidthTx = uint64(mdutil.GetInt(md, keyBandwidthTx))
	l.md.bandwidthRx = uint64(mdutil.GetInt(md, keyBandwidthRx))
	l.md.disableUDP = mdutil.GetBool(md, keyDisableUDP)

	if mdutil.GetBool(md, keyKeepAlive) {
		l.md.keepAlivePeriod = mdutil.GetDuration(md, keyTTL)
		if l.md.keepAlivePeriod <= 0 {
			l.md.keepAlivePeriod = 10 * time.Second
		}
	}
	l.md.handshakeTimeout = mdutil.GetDuration(md, keyHandshakeTimeout)
	l.md.maxIdleTimeout = mdutil.GetDuration(md, keyMaxIdleTimeout)

	l.md.backlog = mdutil.GetInt(md, keyBacklog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	return
}
