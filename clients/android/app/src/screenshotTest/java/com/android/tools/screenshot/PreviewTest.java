package com.android.tools.screenshot;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.platform.commons.annotation.Testable;

/**
 * Source-compatible marker for the alpha16 screenshot engine.
 *
 * The published alpha16 validation API carries Kotlin 2.2 metadata while this application is
 * intentionally pinned to Kotlin 2.0. The engine discovers the stable annotation name at runtime;
 * keeping this marker in the screenshot-only source set avoids changing the production toolchain.
 */
@Documented
@Testable
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface PreviewTest {}
