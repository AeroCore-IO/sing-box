package turbine

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWhitelistMatchDomain(t *testing.T) {
	whitelist, err := NewWhitelist([]string{"*.pubg.com", "api.example.com"}, nil)
	require.NoError(t, err)
	require.True(t, whitelist.MatchDomain("game.pubg.com"))
	require.True(t, whitelist.MatchDomain("api.example.com"))
	require.False(t, whitelist.MatchDomain("evil.com"))
}

func TestWhitelistExactDomainNotSuffix(t *testing.T) {
	whitelist, err := NewWhitelist([]string{"api.example.com"}, nil)
	require.NoError(t, err)
	require.True(t, whitelist.MatchDomain("api.example.com"))
	require.False(t, whitelist.MatchDomain("foo.api.example.com"))
}

func TestWhitelistEmpty(t *testing.T) {
	whitelist, err := NewWhitelist(nil, nil)
	require.NoError(t, err)
	require.True(t, whitelist.Empty())
	require.False(t, whitelist.HasActiveGames())
	require.False(t, whitelist.MatchDomain("example.com"))
}

func TestMergeRawWhitelists(t *testing.T) {
	whitelist, err := MergeRawWhitelists(
		[][]string{{"*.a.com"}, {"b.com"}},
		[][]string{{"203.0.113.0/24"}},
	)
	require.NoError(t, err)
	require.False(t, whitelist.Empty())
	require.True(t, whitelist.MatchDomain("x.a.com"))
	require.True(t, whitelist.MatchDomain("b.com"))
}

func TestCheckDomainWhitelistActiveGamesEmpty(t *testing.T) {
	whitelist := withActiveGames(&Whitelist{empty: true}, true)
	require.Error(t, checkDomainWhitelist("evil.com", whitelist))
}

func TestCheckDomainWhitelistNoActiveGames(t *testing.T) {
	whitelist := withActiveGames(&Whitelist{empty: true}, false)
	require.NoError(t, checkDomainWhitelist("any.com", whitelist))
}
