// Package hostlink holds the token server.AddonHost asks for, so that only
// this module, which can name it, reaches the server's side of the add-on
// handle (internal/addonhost).
package hostlink

// Token is what server.AddonHost and server.AddonFixtures ask for. Nothing
// outside this module can name it, so nothing outside can make one.
//
// It has an unexported field so that no value from elsewhere converts to it:
// with none, an untyped struct{}{} would, and code in any module could reach
// the handle. A struct rather than a pointer, which nil would satisfy.
type Token struct{ _ byte }
