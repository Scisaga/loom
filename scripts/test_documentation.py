"""文档移动后要检出失效入链，同时允许协议示例中的 Markdown 文本。"""

from pathlib import Path
import tempfile
import unittest

import check_documentation as doc


class DocumentationTest(unittest.TestCase):
    def test_anchors_preserve_unicode_duplicates_and_explicit_ids(self):
        source = '# 入口 · v2\n## `Device` 状态\n## `Device` 状态\n<a id="old-section"></a>\n'
        self.assertEqual(doc.anchors(source), {"入口--v2", "device-状态", "device-状态-1", "old-section"})

    def test_code_examples_are_not_references(self):
        source = '~~~md\n# 假章节\n[示例](missing.md)\n~~~\n[有效](guide.md#流程)\n'
        self.assertEqual(doc.links(source), [(5, "guide.md#流程")])
        self.assertEqual(doc.anchors(source), set())

    def test_moved_documents_require_valid_incoming_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docs = root / "docs"
            docs.mkdir()
            entry = docs / "README.md"
            guide = docs / "guide.md"
            orphan = docs / "orphan.md"
            entry.write_text('# 导航\n[规程](guide.md#旧章节)\n')
            guide.write_text('# 新章节\n')
            orphan.write_text('# 未引用的规范\n')
            errors = doc.check(root, [entry, guide, orphan])
            self.assertTrue(any('章节不存在' in error for error in errors))
            self.assertTrue(any('入口不可达' in error for error in errors))
            guide.write_text('# 新章节\n<a id="旧章节"></a>\n[背景](orphan.md)\n')
            self.assertEqual(doc.check(root, [entry, guide, orphan]), [])

    def test_private_or_missing_document_cannot_be_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            entry = root / "docs/README.md"
            private = root / "private.md"
            private.write_text('# 私有\n')
            entry.write_text('# 导航\n[私有](../private.md)\n[缺失](missing.md)\n')
            errors = doc.check(root, [entry])
            self.assertTrue(any('未纳入版本' in error for error in errors))
            self.assertTrue(any('文件不存在' in error for error in errors))

    def test_code_and_retired_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs/status").mkdir(parents=True)
            entry = root / "docs/README.md"
            code = root / "docs/tool.go"
            entry.write_text('# 导航\n')
            code.write_text('package main\n')
            errors = doc.check(root, [entry, code])
            self.assertTrue(any('已退役' in error for error in errors))
            self.assertTrue(any('代码和产物须归位' in error for error in errors))


if __name__ == "__main__":
    unittest.main()
