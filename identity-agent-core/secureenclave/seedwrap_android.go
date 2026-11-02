//go:build android

package secureenclave

// A phone is one of the places a root identity is meant to live, and the
// Android Keystore/StrongBox seed wrapper is not written yet. Until it is, a
// seed on Android is stored unwrapped, as it always was, and the envelope says
// exactly that and why. Replacing this with a wrapper is its own task.
func platformUnwrappedReason() string {
	return "android: the Keystore/StrongBox seed wrapper is not written yet, " +
		"so this seed is stored unwrapped under the app's private storage"
}
