#!/usr/bin/env python3
"""从指定的 v4 SVG 生成桌面自适应图标与 APK 内的普通密度图标。"""

from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "clients/android/app/src/main/res"
SVG = "http://www.w3.org/2000/svg"


def main():
    source = ET.parse(ROOT / "assets/loom-logo-v4.svg").getroot()
    group = source.find(f"{{{SVG}}}g")
    gradient = source.find(f"{{{SVG}}}defs/{{{SVG}}}linearGradient")
    assert group is not None and gradient is not None
    assert source.attrib["viewBox"].split() == ["0", "0", "1254.000000", "1254.000000"]
    paths = group.findall(f"{{{SVG}}}path")
    assert paths[0].get("fill") == "#fafaf7"
    assert all(path.get("fill") == "#5b6166" for path in paths[1:])
    # v4 的背景色镂空转换为真实透明孔，缩放后仍与下层渐变连续。
    compound = " ".join(" ".join(path.attrib["d"].split()) for path in paths)
    stops = gradient.findall(f"{{{SVG}}}stop")
    start, end = (stop.attrib["stop-color"].upper() for stop in stops)
    foreground = paths[0].attrib["fill"].upper()

    (RES / "values/colors.xml").write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<!-- Generated from assets/loom-logo-v4.svg by scripts/generate_android_launcher_icons.py. -->
<resources>
    <color name="loom_launcher_gradient_start">{start}</color>
    <color name="loom_launcher_gradient_end">{end}</color>
    <color name="loom_launcher_foreground">{foreground}</color>
</resources>
''')
    (RES / "drawable/ic_loom_launcher_mark.xml").write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<!-- Generated from assets/loom-logo-v4.svg by scripts/generate_android_launcher_icons.py. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp" android:height="108dp"
    android:viewportWidth="1254" android:viewportHeight="1254">
    <group android:translateY="1254" android:scaleY="-1">
        <path android:fillColor="@color/loom_launcher_foreground" android:fillType="evenOdd"
            android:pathData="{compound}" />
    </group>
</vector>
''')
    (RES / "drawable/ic_loom_launcher_foreground.xml").write_text('''<?xml version="1.0" encoding="utf-8"?>
<!-- 保留 v4 画布留白；可见图案比原先紧裁切的前景缩小约 15%。 -->
<inset xmlns:android="http://schemas.android.com/apk/res/android"
    android:drawable="@drawable/ic_loom_launcher_mark"
    android:insetLeft="20%" android:insetTop="20%"
    android:insetRight="20%" android:insetBottom="20%" />
''')
    (RES / "drawable/ic_loom_launcher_background.xml").write_text('''<?xml version="1.0" encoding="utf-8"?>
<!-- 中央可见区域保留 v4 渐变；自适应图标的外缘继续延伸背景。 -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:aapt="http://schemas.android.com/aapt"
    android:width="108dp" android:height="108dp"
    android:viewportWidth="108" android:viewportHeight="108">
    <path android:pathData="M0,0H108V108H0Z">
        <aapt:attr name="android:fillColor">
            <gradient android:type="linear" android:startX="18" android:startY="18"
                android:endX="90" android:endY="90" android:tileMode="clamp"
                android:startColor="@color/loom_launcher_gradient_start"
                android:endColor="@color/loom_launcher_gradient_end" />
        </aapt:attr>
    </path>
</vector>
''')

    # 普通 PNG 与自适应图标的中央可见区域使用相同图案比例。
    normal_svg = f'''<svg xmlns="{SVG}" width="1254" height="1254" viewBox="0 0 1254 1254">
<defs><linearGradient id="background" x1="0" y1="0" x2="1254" y2="1254" gradientUnits="userSpaceOnUse">
<stop offset="0" stop-color="{start}"/><stop offset="1" stop-color="{end}"/>
</linearGradient></defs>
<rect width="1254" height="1254" fill="url(#background)"/>
<g transform="translate(62.7 62.7) scale(0.9)">
<g transform="translate(0 1254) scale(1 -1)">
<path fill="{foreground}" fill-rule="evenodd" d="{compound}"/>
</g></g></svg>'''
    with tempfile.TemporaryDirectory(prefix="loom-android-icon-") as folder:
        svg = Path(folder) / "icon.svg"
        svg.write_text(normal_svg)
        for density, size in (("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)):
            directory = RES / f"mipmap-{density}"
            directory.mkdir(exist_ok=True)
            subprocess.run(["rsvg-convert", "-w", str(size), "-h", str(size),
                "-o", str(directory / "ic_launcher.png"), str(svg)], check=True)


if __name__ == "__main__":
    main()
