package utils

const (
	Critical = iota
	Error
	Warning
	Info
	Debug
	Trace
)

var log_level int = 0

func SetLogLevel(level int) {
	log_level = level
}

func GetLogLevel() int {
	return log_level
}
