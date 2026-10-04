// Package loomcore is the narrow gomobile boundary for the Android host.
package loomcore

const bindingVersion = "android-schema3"

// Version proves that the APK loaded the shared schema-3 binding.
func Version() string { return bindingVersion }
