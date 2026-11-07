// Package e2e holds the live tests against SSLMate and Validin (build tag
// "e2e", run by make e2e). They skip unless CERT_LOOKUP_SSLMATE_API_KEY is
// set; the history test also needs CERT_LOOKUP_VALIDIN_API_KEY. A run spends
// about six SSLMate single-host queries (of 100 an hour) and one Validin query
// (of 10 a day).
package e2e
