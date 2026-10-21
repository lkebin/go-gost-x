package logger

import (
	corelogger "github.com/go-gost/core/logger"
)

// lateLogger forwards every log call to the current global default logger,
// with its own fields attached at call time.
//
// Components are constructed while a configuration is being loaded, but the
// host application may install its own default logger afterwards: gost's CLI
// does, and embedding applications (e.g. the GostX app) replace the logger
// installed by loader.Load with one that writes to their in-app log. A logger
// captured at construction time would keep writing to the throwaway logger
// loader.Load installs, so components created from config would log to a sink
// nobody watches. Delegating at call time keeps them attached to whichever
// logger is current.
type lateLogger struct {
	fields map[string]any
}

// LateLogger returns a logger that resolves the global default logger when a
// message is logged rather than when it is created.
func LateLogger() corelogger.Logger {
	return &lateLogger{}
}

func (l *lateLogger) target() corelogger.Logger {
	d := corelogger.Default()
	if d == nil {
		return Nop()
	}
	if len(l.fields) == 0 {
		return d
	}
	return d.WithFields(l.fields)
}

func (l *lateLogger) WithFields(fields map[string]any) corelogger.Logger {
	if len(fields) == 0 {
		return l
	}
	merged := make(map[string]any, len(l.fields)+len(fields))
	for k, v := range l.fields {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return &lateLogger{fields: merged}
}

func (l *lateLogger) Trace(args ...any)                 { l.target().Trace(args...) }
func (l *lateLogger) Tracef(format string, args ...any) { l.target().Tracef(format, args...) }
func (l *lateLogger) Debug(args ...any)                 { l.target().Debug(args...) }
func (l *lateLogger) Debugf(format string, args ...any) { l.target().Debugf(format, args...) }
func (l *lateLogger) Info(args ...any)                  { l.target().Info(args...) }
func (l *lateLogger) Infof(format string, args ...any)  { l.target().Infof(format, args...) }
func (l *lateLogger) Warn(args ...any)                  { l.target().Warn(args...) }
func (l *lateLogger) Warnf(format string, args ...any)  { l.target().Warnf(format, args...) }
func (l *lateLogger) Error(args ...any)                 { l.target().Error(args...) }
func (l *lateLogger) Errorf(format string, args ...any) { l.target().Errorf(format, args...) }
func (l *lateLogger) Fatal(args ...any)                 { l.target().Fatal(args...) }
func (l *lateLogger) Fatalf(format string, args ...any) { l.target().Fatalf(format, args...) }

func (l *lateLogger) GetLevel() corelogger.LogLevel { return l.target().GetLevel() }

func (l *lateLogger) IsLevelEnabled(level corelogger.LogLevel) bool {
	return l.target().IsLevelEnabled(level)
}
