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
            (docs / "architecture").mkdir()
            guide = docs / "architecture/guide.md"
            orphan = docs / "architecture/orphan.md"
            entry.write_text('# 导航\n[规程](architecture/guide.md#旧章节)\n')
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

    def test_flat_documents_prompts_and_history_cannot_return(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs/decisions").mkdir(parents=True)
            (root / "docs/development").mkdir()
            entry = root / "docs/README.md"
            flat = root / "docs/design.md"
            prompt = root / "docs/development/work-prompt.md"
            entry.write_text('# 导航\n[架构](design.md)\n[开发](development/work-prompt.md)\n')
            flat.write_text('# 架构\n')
            prompt.write_text('# 接续会话\n')
            errors = doc.check(root, [entry, flat, prompt])
            self.assertTrue(any('根目录只保留' in error for error in errors))
            self.assertTrue(any('会话提示词' in error for error in errors))
            self.assertTrue(any('已退役目录' in error for error in errors))

    def test_semantic_topics_replace_numbered_headings_and_citations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs/architecture").mkdir(parents=True)
            entry = root / "docs/README.md"
            guide = root / "docs/architecture/guide.md"
            entry.write_text('# 导航\n[上报](architecture/guide.md)\n')
            guide.write_text('# 16.2 上报\n沿用 §16.2 和 D81。\n[](guide.md)\n')
            errors = doc.check(root, [entry, guide])
            self.assertTrue(any('标题应按主题' in error for error in errors))
            self.assertTrue(any('旧编号引用' in error for error in errors))
            self.assertTrue(any('链接文字为空' in error for error in errors))
            guide.write_text(
                '# 上报\n## v2 信任边界\n直接说明规则。\n```text\n'
                '# 16.2 数据示例\n'
                'D81\n```\n'
            )
            self.assertEqual(doc.check(root, [entry, guide]), [])


if __name__ == "__main__":
    unittest.main()
