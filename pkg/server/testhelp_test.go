package server

import "fmt"

func logSprintf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}
