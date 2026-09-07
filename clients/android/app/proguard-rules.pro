# libbox and loomcore are generated gomobile bindings. Their JNI entry points
# are referenced by generated native names, not by ordinary Kotlin calls.
-keep class go.** { *; }
-keep class io.github.scisaga.libbox.** { *; }
-keep class io.github.scisaga.loomcore.** { *; }
