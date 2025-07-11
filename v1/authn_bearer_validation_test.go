package doorman

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

type testCase struct {
	key      string
	vo       *ValidationOperation
	expected bool
}

var (
	testToken jwt.MapClaims = jwt.MapClaims{
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

	// test cases
	testCases = []testCase{
		// length
		testCase{key: "keyString01", vo: &ValidationOperation{Operation: "length", Value: 4}, expected: true},
		testCase{key: "keyString01", vo: &ValidationOperation{Operation: "length", Value: int64(4)}, expected: true},
		testCase{key: "keyString01", vo: &ValidationOperation{Operation: "length", Value: 5}, expected: false},
		testCase{key: "keyString01", vo: &ValidationOperation{Operation: "length", Value: int8(5)}, expected: false},
		testCase{key: "keyNumber01", vo: &ValidationOperation{Operation: "length", Value: 4}, expected: true},
		testCase{key: "keyNumber01", vo: &ValidationOperation{Operation: "length", Value: 6}, expected: false},
		testCase{key: "slice01", vo: &ValidationOperation{Operation: "length", Value: 3}, expected: true},
		testCase{key: "slice03", vo: &ValidationOperation{Operation: "length", Value: 3}, expected: true},
		testCase{key: "dict01", vo: &ValidationOperation{Operation: "length", Value: 3}, expected: true},
		// type
		testCase{key: "keyString01", vo: &ValidationOperation{Operation: "type", Value: "string"}, expected: true},
		testCase{key: "keyNumber01", vo: &ValidationOperation{Operation: "type", Value: "number"}, expected: true},
		testCase{key: "keyNumber03", vo: &ValidationOperation{Operation: "type", Value: "number"}, expected: true},
		testCase{key: "keyBool01", vo: &ValidationOperation{Operation: "type", Value: "bool"}, expected: true},
		testCase{key: "dict01", vo: &ValidationOperation{Operation: "type", Value: "map"}, expected: true},
		testCase{key: "dict01", vo: &ValidationOperation{Operation: "type", Value: "list"}, expected: false},
		testCase{key: "slice01", vo: &ValidationOperation{Operation: "type", Value: "list"}, expected: true},
		// contains
		testCase{key: "keyString01", vo: &ValidationOperation{Operation: "contains", Value: 4}, expected: false},
		testCase{key: "keyString01", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		testCase{key: "keyNumber01", vo: &ValidationOperation{Operation: "contains", Value: 4}, expected: true},
		testCase{key: "keyNumber01", vo: &ValidationOperation{Operation: "contains", Value: 5}, expected: false},
		testCase{key: "slice01", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		testCase{key: "slice01", vo: &ValidationOperation{Operation: "contains", Value: 5}, expected: false},
		testCase{key: "slice03", vo: &ValidationOperation{Operation: "contains", Value: 5}, expected: false},
		testCase{key: "slice03", vo: &ValidationOperation{Operation: "contains", Value: 3}, expected: true},
		testCase{key: "slice03", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		testCase{key: "dict01.nestedKey01", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		testCase{key: "dict01.slice01", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		// equal
		testCase{key: "keyBool01", vo: &ValidationOperation{Operation: "equal", Value: true}, expected: true},
		testCase{key: "keyBool01", vo: &ValidationOperation{Operation: "equal", Value: false}, expected: false},
		testCase{key: "keyString01", vo: &ValidationOperation{Operation: "equal", Value: "abcd"}, expected: true},
		testCase{key: "keyNumber01", vo: &ValidationOperation{Operation: "equal", Value: 4}, expected: true},
		testCase{key: "keyNumber01", vo: &ValidationOperation{Operation: "equal", Value: 10}, expected: false},
		testCase{key: "dict01.nestedKey01", vo: &ValidationOperation{Operation: "equal", Value: "a"}, expected: false},
	}
)

func TestGetToken(t *testing.T) {
	v := getFromTokenPayload("keyString01", testToken)
	if sv, ok := v.(string); !ok || sv != "abcd" {
		t.Errorf("getFromTokenPayload returned unexpected value: %v", sv)
	}

	v = getFromTokenPayload("keyNumber01", testToken)
	if sv, ok := v.(int); !ok || sv != 4 {
		t.Errorf("getFromTokenPayload returned unexpected value: %v", sv)
	}

	v = getFromTokenPayload("slice01", testToken)
	if sv, ok := v.([]any); !ok || len(sv) != 3 {
		t.Errorf("getFromTokenPayload returned unexpected value: %v", sv)
	}

	v = getFromTokenPayload("dict01.nestedKey01", testToken)
	if sv, ok := v.(string); !ok || sv != "abcd" {
		t.Errorf("getFromTokenPayload returned unexpected value: %v", sv)
	}
}

func TestValidationOperations(t *testing.T) {
	for idx, tc := range testCases {
		t.Logf("tc[%d]: running test case for key '%s' : operation: %s", idx, tc.key, tc.vo.Operation)
		keyValue := getFromTokenPayload(tc.key, testToken)
		if cvo, found := claimValidationOperations[tc.vo.Operation]; found {
			result, err := cvo(tc.vo, keyValue)
			if err != nil {
				t.Errorf("tc[%d]: %v returned error: %v", idx, tc.vo, err)
			}
			if result != tc.expected {
				t.Errorf("tc[%d]: %v did not return expected result (expected=%t , result=%t)", idx, tc.vo, tc.expected, result)
			}
		} else {
			t.Errorf("tc[%d]: claimValidationOperations[%v] not found", idx, tc.vo.Operation)
		}

	}

}
