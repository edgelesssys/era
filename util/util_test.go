package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringSliceContains(t *testing.T) {
	assert := assert.New(t)
	assert.False(StringSliceContains(nil, ""))
	assert.False(StringSliceContains([]string{}, ""))
	assert.False(StringSliceContains(nil, "foo"))
	assert.False(StringSliceContains([]string{}, "foo"))
	assert.True(StringSliceContains([]string{"xx", "foo", "xx"}, "foo"))
	assert.False(StringSliceContains([]string{"xx", "bar", "xx"}, "foo"))
}
