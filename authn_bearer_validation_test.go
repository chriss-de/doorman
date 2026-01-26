package doorman

import (
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

type testCase struct {
	key      string
	vo       *ValidationOperation
	expected bool
}

var (
	testTokenValidation = jwt.MapClaims{
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
		{key: "keyString01", vo: &ValidationOperation{Operation: "length", Value: 4}, expected: true},
		{key: "keyString01", vo: &ValidationOperation{Operation: "length", Value: int64(4)}, expected: true},
		{key: "keyString01", vo: &ValidationOperation{Operation: "length", Value: 5}, expected: false},
		{key: "keyString01", vo: &ValidationOperation{Operation: "length", Value: int8(5)}, expected: false},
		{key: "keyNumber01", vo: &ValidationOperation{Operation: "length", Value: 4}, expected: true},
		{key: "keyNumber01", vo: &ValidationOperation{Operation: "length", Value: 6}, expected: false},
		{key: "slice01", vo: &ValidationOperation{Operation: "length", Value: 3}, expected: true},
		{key: "slice03", vo: &ValidationOperation{Operation: "length", Value: 3}, expected: true},
		{key: "dict01", vo: &ValidationOperation{Operation: "length", Value: 3}, expected: true},
		// type
		{key: "keyString01", vo: &ValidationOperation{Operation: "type", Value: "string"}, expected: true},
		{key: "keyNumber01", vo: &ValidationOperation{Operation: "type", Value: "number"}, expected: true},
		{key: "keyNumber03", vo: &ValidationOperation{Operation: "type", Value: "number"}, expected: true},
		{key: "keyBool01", vo: &ValidationOperation{Operation: "type", Value: "bool"}, expected: true},
		{key: "dict01", vo: &ValidationOperation{Operation: "type", Value: "map"}, expected: true},
		{key: "dict01", vo: &ValidationOperation{Operation: "type", Value: "list"}, expected: false},
		{key: "slice01", vo: &ValidationOperation{Operation: "type", Value: "list"}, expected: true},
		// contains
		{key: "keyString01", vo: &ValidationOperation{Operation: "contains", Value: 4}, expected: false},
		{key: "keyString01", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		{key: "keyNumber01", vo: &ValidationOperation{Operation: "contains", Value: 4}, expected: true},
		{key: "keyNumber01", vo: &ValidationOperation{Operation: "contains", Value: 5}, expected: false},
		{key: "slice01", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		{key: "slice01", vo: &ValidationOperation{Operation: "contains", Value: 5}, expected: false},
		{key: "slice03", vo: &ValidationOperation{Operation: "contains", Value: 5}, expected: false},
		{key: "slice03", vo: &ValidationOperation{Operation: "contains", Value: 3}, expected: true},
		{key: "slice03", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		{key: "dict01.nestedKey01", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		{key: "dict01.slice01", vo: &ValidationOperation{Operation: "contains", Value: "a"}, expected: true},
		// equal
		{key: "keyBool01", vo: &ValidationOperation{Operation: "equal", Value: true}, expected: true},
		{key: "keyBool01", vo: &ValidationOperation{Operation: "equal", Value: false}, expected: false},
		{key: "keyString01", vo: &ValidationOperation{Operation: "equal", Value: "abcd"}, expected: true},
		{key: "keyNumber01", vo: &ValidationOperation{Operation: "equal", Value: 4}, expected: true},
		{key: "keyNumber01", vo: &ValidationOperation{Operation: "equal", Value: 10}, expected: false},
		{key: "dict01.nestedKey01", vo: &ValidationOperation{Operation: "equal", Value: "a"}, expected: false},

		// or/and/not
		{key: "keyNumber02", vo: &ValidationOperation{Operation: "or", Value: []*ValidationOperation{
			{Operation: "equal", Value: 10},
			{Operation: "equal", Value: "10"},
		}}, expected: true},
		{key: "keyNumber02", vo: &ValidationOperation{Operation: "and", Value: []*ValidationOperation{
			{Operation: "equal", Value: 10},
			{Operation: "equal", Value: "10"},
		}}, expected: false},
		{key: "slice01", vo: &ValidationOperation{Operation: "and", Value: []*ValidationOperation{
			{Operation: "contains", Value: "a"},
			{Operation: "length", Value: 3},
		}}, expected: true},
		{key: "slice01", vo: &ValidationOperation{Operation: "and", Value: []*ValidationOperation{
			{Operation: "contains", Value: "a"},
			{Operation: "not", Value: &ValidationOperation{Operation: "length", Value: 10}},
		}}, expected: true},
	}
)

func TestValidationOperations(t *testing.T) {
	for idx, tc := range testCases {
		t.Run(fmt.Sprintf("tc[%d]: running test case for key '%s' : operation: %s", idx, tc.key, tc.vo.Operation), func(t *testing.T) {
			t.Parallel()
			keyValue := getFromTokenPayload(tc.key, testTokenValidation)
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
		})

	}

}
