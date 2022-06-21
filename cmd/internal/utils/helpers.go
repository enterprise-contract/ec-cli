package utils

import (
	"bytes"
	"github.com/ghodss/yaml"
	"github.com/spf13/afero"
	"unicode"
)

var (
	AppFS  = afero.NewOsFs()
)

// ToJSON converts a single YAML document into a JSON document
// or returns an error. If the document appears to be JSON the
// YAML decoding path is not used.
func ToJSON(data []byte) ([]byte, error) {
	if hasJSONPrefix(data) {
		return data, nil
	}
	return yaml.YAMLToJSON(data)
}

var jsonPrefix = []byte("{")

// hasJSONPrefix returns true if the provided buffer appears to start with
// a JSON open brace.
func hasJSONPrefix(buf []byte) bool {
	return hasPrefix(buf, jsonPrefix)
}

// Return true if the first non-whitespace bytes in buf is prefix.
func hasPrefix(buf []byte, prefix []byte) bool {
	trim := bytes.TrimLeftFunc(buf, unicode.IsSpace)
	return bytes.HasPrefix(trim, prefix)
}


