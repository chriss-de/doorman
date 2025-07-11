package doorman

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

var (
	testTokenBearer = jwt.MapClaims{
		"keyString01": "abcd",
		"keyString02": "abcdef",
		"keyNumber01": 4,
		"keyNumber02": 10,
		"keyNumber03": int64(10),
		"keyBool01":   true,
		"slice01":     []any{"a", "b", "c"},
		"slice02":     []any{1, 2, 3},
		"slice03":     []any{"a", "b", 3},
		"dict01": map[string]any{
			"nestedKey01": "abcd",
			"nestedKey02": 1,
			"slice01":     []any{"a", "b", "c"},
		},
	}
)

func TestGetToken(t *testing.T) {
	v := getFromTokenPayload("keyString01", testTokenBearer)
	if sv, ok := v.(string); !ok || sv != "abcd" {
		t.Errorf("getFromTokenPayload returned unexpected value: %v", sv)
	}

	v = getFromTokenPayload("keyNumber01", testTokenBearer)
	if sv, ok := v.(int); !ok || sv != 4 {
		t.Errorf("getFromTokenPayload returned unexpected value: %v", sv)
	}

	v = getFromTokenPayload("slice01", testTokenBearer)
	if sv, ok := v.([]any); !ok || len(sv) != 3 {
		t.Errorf("getFromTokenPayload returned unexpected value: %v", sv)
	}

	v = getFromTokenPayload("dict01.nestedKey01", testTokenBearer)
	if sv, ok := v.(string); !ok || sv != "abcd" {
		t.Errorf("getFromTokenPayload returned unexpected value: %v", sv)
	}
}
