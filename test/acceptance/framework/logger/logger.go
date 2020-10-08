package logger

import (
	"fmt"
	"testing"
	"time"

	terratestTesting "github.com/gruntwork-io/terratest/modules/testing"
)

// todo: add docs
type TestLogger struct{}

func (tl TestLogger) Logf(t terratestTesting.TestingT, format string, args ...interface{}) {
	Logf(t, format, args...)
}

func (tl TestLogger) Log(t terratestTesting.TestingT, args ...interface{}) {
	Log(t, args)
}

func Logf(t terratestTesting.TestingT, format string, args ...interface{}) {
	log := fmt.Sprintf(format, args...)
	Log(t, log)
}

func Log(t terratestTesting.TestingT, args ...interface{}) {
	tt, ok := t.(*testing.T)
	if !ok {
		t.Error("failed to cast")
	}

	allArgs := []interface{}{time.Now().Format(time.RFC3339)}
	allArgs = append(allArgs, args...)
	tt.Log(allArgs...)
}
