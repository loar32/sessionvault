package profiles

import "regexp"

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func ValidName(name string) bool { return validName.MatchString(name) }
