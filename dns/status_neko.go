package dns

// HTTPStatusError is a DoH server's answer other than 200 (neko): its status code, for a client that tells a
// credential the server refused (a raycontrol node answers a DoH token it no longer takes with 404, or 403 by the
// mode of its site) from a path that fails. The text is the transports' as before.
type HTTPStatusError struct {
	StatusCode int
	Status     string
}

func (e *HTTPStatusError) Error() string {
	return "unexpected status: " + e.Status
}
