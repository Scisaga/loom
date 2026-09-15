#!/usr/bin/env python3

import unittest

from install_confirmation import SafetyCountdown, find_confirmation


def screen(app_label: str, actions: str) -> str:
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<hierarchy rotation="0">
  <node text="{app_label}" clickable="false" bounds="[0,0][1080,200]" />
  {actions}
</hierarchy>'''


class InstallConfirmationTest(unittest.TestCase):
    def test_finds_nested_enabled_install_action(self):
        xml = screen(
            "Loom",
            '''<node text="" clickable="true" enabled="true" bounds="[700,1800][1040,1940]">
                 <node text="继续安装" clickable="false" bounds="[760,1840][980,1900]" />
               </node>''',
        )
        self.assertEqual((870, 1870, "继续安装"), find_confirmation(xml))

    def test_rejects_screen_without_loom_identity(self):
        xml = screen("Another app", '<node text="安装" clickable="true" bounds="[0,0][10,10]" />')
        with self.assertRaises(ValueError):
            find_confirmation(xml)

    def test_rejects_disabled_or_ambiguous_actions(self):
        disabled = screen(
            "Loom",
            '<node text="Install" clickable="true" enabled="false" bounds="[0,0][10,10]" />',
        )
        with self.assertRaises(ValueError):
            find_confirmation(disabled)

        ambiguous = screen(
            "Loom",
            '<node text="Install" clickable="true" bounds="[0,0][10,10]" />'
            '<node text="Continue" clickable="true" bounds="[20,0][30,10]" />',
        )
        with self.assertRaises(ValueError):
            find_confirmation(ambiguous)

    def test_accepts_enabled_install_before_automatic_rejection(self):
        counting_down = screen(
            "io.github.scisaga.loom.test",
            '<node text="继续安装" clickable="true" enabled="true" bounds="[0,0][10,10]" />'
            '<node text="拒绝（8）" clickable="true" enabled="true" bounds="[20,0][30,10]" />',
        )
        self.assertEqual((5, 5, "继续安装"), find_confirmation(counting_down))

    def test_waits_for_positive_button_countdown(self):
        positive_countdown = screen(
            "Loom",
            '<node text="Continue (3)" clickable="true" enabled="true" bounds="[0,0][10,10]" />',
        )
        with self.assertRaises(SafetyCountdown) as positive:
            find_confirmation(positive_countdown)
        self.assertEqual(3, positive.exception.seconds)


if __name__ == "__main__":
    unittest.main()
