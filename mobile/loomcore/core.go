// Package loomcore is the narrow gomobile boundary for the Android host.
package loomcore

const bindingVersion = "android-v2-minimal-v1"

// Version proves that the APK loaded the v2-minimal binding.
func Version() string { return bindingVersion }
