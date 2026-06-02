package gormstore

import (
	"encoding/json"
)

// encodeStringSlice round-trips a []string through JSON so it can be
// stored in a portable text column. nil is encoded as "null" so the
// column is distinguishable from "[]".
func encodeStringSlice(in []string) (string, error) {
	if in == nil {
		return "null", nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeStringSlice(in string) ([]string, error) {
	if in == "" || in == "null" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(in), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func encodeStringMap(in map[string]string) (string, error) {
	if in == nil {
		return "null", nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeStringMap(in string) (map[string]string, error) {
	if in == "" || in == "null" {
		return nil, nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(in), &out); err != nil {
		return nil, err
	}
	return out, nil
}
