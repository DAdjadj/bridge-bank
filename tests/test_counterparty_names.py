import unittest

from app.sync import _names_someone_else, _same_name


class SameNameTest(unittest.TestCase):
    def test_bank_spellings_of_one_name_match(self):
        self.assertTrue(_same_name("David Alves", "DAVID ADJADJ ALVES"))
        self.assertTrue(_same_name("David Alves", "ALVES DAVID"))
        self.assertTrue(_same_name("Flávio Alves", "FLAVIO ALVES"))

    def test_relatives_sharing_a_surname_do_not_match(self):
        self.assertFalse(_same_name("Flávio Alves", "DAVID ADJADJ ALVES"))
        self.assertFalse(_same_name("Alves", "David Alves"))

    def test_empty_names_never_match(self):
        self.assertFalse(_same_name("", ""))
        self.assertFalse(_same_name("David Alves", ""))


class NamesSomeoneElseTest(unittest.TestCase):
    OWN = {"david alves"}

    def test_a_move_between_own_revolut_accounts_names_nobody(self):
        t = {"credit_debit_indicator": "DBIT", "creditor": {},
             "remittance_information": ["To EUR Pro"]}
        self.assertFalse(_names_someone_else(t, self.OWN))

    def test_a_card_payment_names_the_shop(self):
        t = {"credit_debit_indicator": "DBIT", "creditor": {"name": "apple.com/bill"}}
        self.assertTrue(_names_someone_else(t, self.OWN))

    def test_money_from_a_friend_names_the_friend(self):
        t = {"credit_debit_indicator": "CRDT", "debtor": {"name": "Miguel Bastos"},
             "remittance_information": ["YouTube premium mistake"]}
        self.assertTrue(_names_someone_else(t, self.OWN))

    def test_money_from_the_holders_other_bank_is_not_someone_else(self):
        t = {"credit_debit_indicator": "CRDT", "debtor": {"name": "DAVID ADJADJ ALVES"}}
        self.assertFalse(_names_someone_else(t, self.OWN))

    def test_flat_creditor_name_field_is_read_too(self):
        t = {"credit_debit_indicator": "DBIT", "creditor_name": "Mercadona"}
        self.assertTrue(_names_someone_else(t, self.OWN))


if __name__ == "__main__":
    unittest.main()
