package doorman

import (
	"strconv"
	"strings"
)

var claimValidationOperations = map[string]func(*ValidationOperation, any) (bool, error){
	"length":   validationOperationLength,
	"type":     validationOperationIsType,
	"contains": validationOperationContains,
	"equal":    validationOperationEqual,
}

func RegisterBearerValidationOperation(n string, o func(*ValidationOperation, any) (bool, error)) func(dm *Doorman) {
	return func(dm *Doorman) {
		claimValidationOperations[n] = o
	}
}

func validationOperationLength(vo *ValidationOperation, tokenValue any) (bool, error) {
	length, err := strconv.ParseInt(vo.Value, 10, 64)
	if err != nil {
		return false, err
	}

	switch tv := tokenValue.(type) {
	case string:
		if len(tv) == int(length) {
			return true, nil
		}
	case int, int8, int16, int32, int64, float32, float64:
		if tv == length {
			return true, nil
		}
	case []any:
		if len(tv) == int(length) {
			return true, nil
		}
	}
	return false, nil
}

func validationOperationIsType(vo *ValidationOperation, tokenValue any) (bool, error) {
	switch tokenValue.(type) {
	case string:
		if vo.Value == "string" {
			return true, nil
		}
	case int, int8, int16, int32, int64, float32, float64:
		if vo.Value == "number" {
			return true, nil
		}
	case []any:
		if vo.Value == "list" {
			return true, nil
		}
	}
	return false, nil
}

func validationOperationContains(vo *ValidationOperation, tokenValue any) (bool, error) {
	switch tv := tokenValue.(type) {
	case string:
		if strings.Contains(tv, vo.Value) {
			return true, nil
		}
		//case []any:
		//	if slices.Contains(tv, vo.Value) {
		//		return true, nil
		//	}
	}
	return false, nil
}

func validationOperationEqual(vo *ValidationOperation, tokenValue any) (bool, error) {
	switch tv := tokenValue.(type) {
	case string:
		if strings.Compare(tv, vo.Value) == 0 {
			return true, nil
		}
	case int, int8, int16, int32, int64, float32, float64:
		if tv == vo.Value {
			return true, nil
		}
	}
	return false, nil
}
