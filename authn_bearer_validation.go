package doorman

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

var claimValidationOperations = map[string]func(*ValidationOperation, any) (bool, error){}

func init() {
	claimValidationOperations["length"] = validationOperationLength
	claimValidationOperations["type"] = validationOperationIsType
	claimValidationOperations["contains"] = validationOperationContains
	claimValidationOperations["equal"] = validationOperationEqual
	claimValidationOperations["or"] = validationOperationOR
	claimValidationOperations["and"] = validationOperationAND
	claimValidationOperations["not"] = validationOperationNOT
}

func RegisterBearerValidationOperation(n string, o func(*ValidationOperation, any) (bool, error)) func(dm *Doorman) {
	return func(dm *Doorman) {
		claimValidationOperations[n] = o
	}
}

func castAsNumber(t any) (int64, error) {
	switch v := t.(type) {
	case float64:
		return int64(v), nil
	case float32:
		return int64(v), nil
	case int64:
		return v, nil
	case int32:
		return int64(v), nil
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	default:
		return int64(0), fmt.Errorf("invalid type %T", t)
	}
}

func castAsString(t any) (string, error) {
	switch v := t.(type) {
	case string:
		return v, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case int32:
		return strconv.FormatInt(int64(v), 10), nil
	case int:
		return strconv.FormatInt(int64(v), 10), nil
	case int8:
		return strconv.FormatInt(int64(v), 10), nil
	default:
		return "", fmt.Errorf("invalid type %T", t)

	}
}

func validationOperationLength(vo *ValidationOperation, tokenValue any) (bool, error) {
	int64Value, err := castAsNumber(vo.Value)
	if err != nil {
		return false, errors.New("invalid type for length")
	}

	switch tv := tokenValue.(type) {
	case string:
		return len(tv) == int(int64Value), nil
	case int:
		return int64(tv) == int64Value, nil
	case int8:
		return int64(tv) == int64Value, nil
	case int16:
		return int64(tv) == int64Value, nil
	case int32:
		return int64(tv) == int64Value, nil
	case int64:
		return tv == int64Value, nil
	case float32:
		return int64(tv) == int64Value, nil
	case float64:
		return int64(tv) == int64Value, nil
	case []any:
		return len(tv) == int(int64Value), nil
	case map[string]any:
		return len(tv) == int(int64Value), nil
	default:
		return false, fmt.Errorf("invalid type %T", tv)
	}
}

func validationOperationIsType(vo *ValidationOperation, tokenValue any) (bool, error) {
	switch tokenValue.(type) {
	case string:
		return vo.Value == "string", nil
	case int, int8, int16, int32, int64, float32, float64:
		return vo.Value == "number", nil
	case []any:
		return vo.Value == "list", nil
	case map[string]any:
		return vo.Value == "map", nil
	case bool:
		return vo.Value == "bool", nil
	}
	return false, nil
}

func validationOperationContains(vo *ValidationOperation, tokenValue any) (bool, error) {
	switch tv := tokenValue.(type) {
	case string:
		strValue, err := castAsString(vo.Value)
		if err != nil {
			return false, err
		}
		if strings.Contains(tv, strValue) {
			return true, nil
		}
	case int, int8, int16, int32, int64, float32, float64:
		if vo.Value == tokenValue {
			return true, nil
		}
	case []any:
		if slices.Contains(tv, vo.Value) {
			return true, nil
		}
		//case map[string]any:

	}
	return false, nil
}

func validationOperationEqual(vo *ValidationOperation, tokenValue any) (bool, error) {
	switch tv := tokenValue.(type) {
	case string:
		strValue, ok := vo.Value.(string)
		if !ok {
			return false, fmt.Errorf("invalid value for equal %T. must be of type string", strValue)
		}
		if strings.Compare(tv, strValue) == 0 {
			return true, nil
		}
	case int, int8, int16, int32, int64, float32, float64:
		if tv == vo.Value {
			return true, nil
		}
	case bool:
		return tv == vo.Value, nil
	}
	return false, nil
}

func validationOperationOR(vo *ValidationOperation, tokenValue any) (bool, error) {
	var (
		result        = false
		validationOps []*ValidationOperation
	)
	if err := mapstructure.Decode(vo.Value, &validationOps); err != nil {
		return false, err
	}

	for _, validation := range validationOps {
		_result, err := processValidationOperation(validation, tokenValue)
		if err != nil {
			return false, err
		}
		result = result || _result
	}
	return result, nil
}

func validationOperationAND(vo *ValidationOperation, tokenValue any) (bool, error) {
	var (
		result        = true
		validationOps []*ValidationOperation
	)
	if err := mapstructure.Decode(vo.Value, &validationOps); err != nil {
		return false, err
	}

	for _, validation := range validationOps {
		_result, err := processValidationOperation(validation, tokenValue)
		if err != nil {
			return false, err
		}
		result = result && _result
	}
	return result, nil
}

func validationOperationNOT(vo *ValidationOperation, tokenValue any) (bool, error) {
	var validationOps *ValidationOperation

	if err := mapstructure.Decode(vo.Value, &validationOps); err != nil {
		return false, err
	}

	_result, err := processValidationOperation(validationOps, tokenValue)
	if err != nil {
		return false, err
	}

	return !_result, nil
}

func processValidationOperation(vo *ValidationOperation, tokenValue any) (bool, error) {
	if cvo, found := claimValidationOperations[vo.Operation]; found {
		result, err := cvo(vo, tokenValue)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
	} else {
		return false, fmt.Errorf("error: invalid validation method")
	}
	return true, nil
}
