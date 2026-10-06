import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PublicSkillTest(unittest.TestCase):
    def test_public_skill_contract(self):
        skill = ROOT / "skills" / "envdirx" / "SKILL.md"
        text = skill.read_text()
        self.assertTrue(text.startswith("---\nname: envdirx\n"))
        self.assertIn("README.md", text)
        self.assertIn("set -c", text)
        self.assertNotIn("/Users/", text)
        self.assertNotIn(".agents/", text)


if __name__ == "__main__":
    unittest.main()
