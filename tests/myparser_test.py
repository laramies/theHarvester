#
# Unit tests for myparser.py
#
import myparser

import unittest

class TestMyParser(unittest.TestCase):

  def test_emails(self):
    word = 'domain.com'
    results = '@domain.com***a@domain***banotherdomain.com***c@domain.com***d@sub.domain.com***'
    p = myparser.parser(results, word)
    emails = sorted(p.emails())
    self.assertEquals(emails, [ 'c@domain.com', 'd@sub.domain.com' ])

if __name__ == '__main__':
  unittest.main()
