package hysteria2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserName(t *testing.T) {
	t.Parallel()
	require.Equal(t, "alice", userName("alice", "secret"))
	require.Equal(t, "", userName("", ""))
	require.NotEqual(t, "secret", userName("", "secret"))
	require.Equal(t, userName("", "secret"), userName("", "secret"))
	require.NotEqual(t, userName("", "a"), userName("", "b"))
}
