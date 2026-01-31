package log

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service/filemanager"
)

var _ Factory = (*defaultFactory)(nil)

type defaultFactory struct {
	ctx               context.Context
	formatter         Formatter
	platformFormatter Formatter
	writer            io.Writer
	file              *os.File
	filePath          string
	platformWriter    PlatformWriter
	needObservable    bool
	level             Level
	subscriber        *observable.Subscriber[Entry]
	observer          *observable.Observer[Entry]
}

func NewDefaultFactory(
	ctx context.Context,
	formatter Formatter,
	writer io.Writer,
	filePath string,
	platformWriter PlatformWriter,
	needObservable bool,
) ObservableFactory {
	factory := &defaultFactory{
		ctx:       ctx,
		formatter: formatter,
		platformFormatter: Formatter{
			BaseTime:         formatter.BaseTime,
			DisableLineBreak: true,
		},
		writer:         writer,
		filePath:       filePath,
		platformWriter: platformWriter,
		needObservable: needObservable,
		level:          LevelTrace,
		subscriber:     observable.NewSubscriber[Entry](128),
	}
	if platformWriter != nil {
		factory.platformFormatter.DisableColors = platformWriter.DisableColors()
	}
	if needObservable {
		factory.observer = observable.NewObserver[Entry](factory.subscriber, 64)
	}
	return factory
}

func (f *defaultFactory) Start() error {
	if f.filePath != "" {
		logFile, err := filemanager.OpenFile(f.ctx, f.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		f.writer = logFile
		f.file = logFile
	}
	return nil
}

func (f *defaultFactory) Close() error {
	return common.Close(
		common.PtrOrNil(f.file),
		f.subscriber,
	)
}

func (f *defaultFactory) Level() Level {
	return f.level
}

func (f *defaultFactory) SetLevel(level Level) {
	f.level = level
}

func (f *defaultFactory) Logger() ContextLogger {
	return f.NewLogger("")
}

func (f *defaultFactory) NewLogger(tag string) ContextLogger {
	return &observableLogger{f, tag}
}

func (f *defaultFactory) Subscribe() (subscription observable.Subscription[Entry], done <-chan struct{}, err error) {
	return f.observer.Subscribe()
}

func (f *defaultFactory) UnSubscribe(sub observable.Subscription[Entry]) {
	f.observer.UnSubscribe(sub)
}

var _ ContextLogger = (*observableLogger)(nil)

type observableLogger struct {
	*defaultFactory
	tag string
}

func safeArgsToString(args []any) (s string) {
	defer func() {
		if r := recover(); r != nil {
			s = fallbackArgsToString(args, r)
		}
	}()
	return F.ToString(args...)
}

func fallbackArgsToString(args []any, panicValue any) string {
	var b strings.Builder
	b.WriteString("log_format_panic=")
	b.WriteString(fmt.Sprint(panicValue))

	// sing-box often passes: ["message", "key=", value, "key=", value, ...]
	// or sometimes a mix of strings/structs. Keep it readable.
	start := 0
	if len(args) > 0 {
		if s, ok := args[0].(string); ok {
			// Heuristic: if it looks like a sentence (spaces/colon), treat as message.
			if strings.ContainsAny(s, " :,") && !strings.HasSuffix(strings.TrimSpace(s), "=") {
				b.WriteString(" msg=")
				b.WriteString(s)
				start = 1
			}
		}
	}

	sanitizeKey := func(k string) (string, bool) {
		k = strings.TrimSpace(k)
		k = strings.TrimRight(k, ",")
		k = strings.TrimRight(k, "=")
		k = strings.TrimSpace(k)
		if k == "" {
			return "", false
		}
		// Disallow keys that look like full sentences.
		if strings.Contains(k, " ") {
			return "", false
		}
		return k, true
	}

	// Try to preserve key/value semantics when possible.
	if (len(args)-start)%2 == 0 {
		okKV := true
		for i := start; i < len(args); i += 2 {
			keyRaw, ok := args[i].(string)
			if !ok {
				okKV = false
				break
			}
			if _, valid := sanitizeKey(keyRaw); !valid {
				okKV = false
				break
			}
		}
		if okKV {
			for i := start; i < len(args); i += 2 {
				keyRaw := args[i].(string)
				key, _ := sanitizeKey(keyRaw)
				b.WriteString(" ")
				b.WriteString(key)
				b.WriteString("=")
				b.WriteString(fmt.Sprint(args[i+1]))
			}
			return b.String()
		}
	}

	b.WriteString(" args=")
	b.WriteString(fmt.Sprint(args))
	return b.String()
}

func (l *observableLogger) Log(ctx context.Context, level Level, args []any) {
	level = OverrideLevelFromContext(level, ctx)
	if level > l.level {
		return
	}
	argsString := safeArgsToString(args)
	nowTime := time.Now()
	if l.needObservable {
		message, messageSimple := l.formatter.FormatWithSimple(ctx, level, l.tag, argsString, nowTime)
		if level == LevelPanic {
			panic(message)
		}
		l.writer.Write([]byte(message))
		if level == LevelFatal {
			os.Exit(1)
		}
		l.subscriber.Emit(Entry{level, messageSimple})
	} else {
		message := l.formatter.Format(ctx, level, l.tag, argsString, nowTime)
		if level == LevelPanic {
			panic(message)
		}
		l.writer.Write([]byte(message))
		if level == LevelFatal {
			os.Exit(1)
		}
	}
	if l.platformWriter != nil {
		l.platformWriter.WriteMessage(level, l.platformFormatter.Format(ctx, level, l.tag, argsString, nowTime))
	}
}

func (l *observableLogger) Trace(args ...any) {
	l.TraceContext(context.Background(), args...)
}

func (l *observableLogger) Debug(args ...any) {
	l.DebugContext(context.Background(), args...)
}

func (l *observableLogger) Info(args ...any) {
	l.InfoContext(context.Background(), args...)
}

func (l *observableLogger) Warn(args ...any) {
	l.WarnContext(context.Background(), args...)
}

func (l *observableLogger) Error(args ...any) {
	l.ErrorContext(context.Background(), args...)
}

func (l *observableLogger) Fatal(args ...any) {
	l.FatalContext(context.Background(), args...)
}

func (l *observableLogger) Panic(args ...any) {
	l.PanicContext(context.Background(), args...)
}

func (l *observableLogger) TraceContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelTrace, args)
}

func (l *observableLogger) DebugContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelDebug, args)
}

func (l *observableLogger) InfoContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelInfo, args)
}

func (l *observableLogger) WarnContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelWarn, args)
}

func (l *observableLogger) ErrorContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelError, args)
}

func (l *observableLogger) FatalContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelFatal, args)
}

func (l *observableLogger) PanicContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelPanic, args)
}
