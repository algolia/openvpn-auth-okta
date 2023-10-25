package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type usernameTest struct {
	testName string
	username string
	res      bool
}

func TestCheckUsernameFormat(t *testing.T) {
	tests := []usernameTest{
		{
			"Valid username - success",
			"dade.murphy@example.com",
			true,
		},
		{
			"Invalid username - failure",
			"dade.*murphy/",
			false,
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			res := CheckUsernameFormat(test.username)
			assert.Equal(t, test.res, res)
		})
	}
}

func TestCheckNotWritable(t *testing.T) {
	t.Run("File does not exist - false", func(t *testing.T) {
		res := CheckNotWritable("MISSING")
		assert.False(t, res)
	})
}

func TestGetEnv(t *testing.T) {
	t.Run("Env var does not exist - falback", func(t *testing.T) {
		res := GetEnv("THIS_ENV_VER_DOES_NOT_EXIST", "value")
		assert.Equal(t, res, "value")
	})
	t.Run("Env var is empty - falback", func(t *testing.T) {
		_ = os.Setenv("THIS_ENV_VAR_IS_EMPTY", "")
		res := GetEnv("THIS_ENV_VAR_IS_EMPTY", "value")
		_ = os.Unsetenv("THIS_ENV_VAR_IS_EMPTY")
		assert.Equal(t, res, "value")
	})
}
