package logsafe

import (
	"fmt"
	"strings"
)

// Value renders dynamic log data on one physical line.
func Value(value interface{}) string {
	text := fmt.Sprint(value)
	text = strings.ReplaceAll(text, "\r", "")
	return strings.ReplaceAll(text, "\n", " ")
}
