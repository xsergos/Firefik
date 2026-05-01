package api

import "regexp"

var containerIDRe = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

func isValidContainerID(id string) bool {
	return containerIDRe.MatchString(id)
}
