import unittest
import passwordmanager.data_security as datasec

class DataSecurityTests(unittest.TestCase):
    TESTDATA_HASHES = [
        ['some test data', b')NG;!\xc3\x11\xf7N\xcfp|\x88 \x114\xf2<\xdd\x94\xf0\xd2\xd4\n\x14x\xd4\x7fX%\x05\xc4\x8c\xaf@6slx\x99]\xd5^\x8d\xab\x84\xce<\xd9\xbf\x0fK\x05\xcb\xf2>\xe4\xa0\x1cY<E\xf7\xf5'],
        ['different test data', b'\xa1N`\xb3J\xc42Ty\xa0\x1f\x19\xb9\x82\xe3\x9d\xc4\\\xa8\xe0S\xc2\x1c\xe8\x13]r\xbc\xf1\x8f\xf0k\x04\xe3\xc0}\x8b\x12\xa5=\xb9\x82:\xda\x08\xdc\x18f\xa3\xc3Y\x04\x84\xd4\xf4\xf3\x91\x98\xed\xfb\x8b\x8d8\xea'],
        ['example password', b'\x04\xec\xb6/!\xa2\xd2gel,\x0f\x9b\x1f\xe7E\x1d)\xe6\xd7\xbe3\xa2Q\x81\xa8"\x17$\xe8\xb2\xc1\xfb\xe3E9\x98\xda\xdc`\xdec)L\xde\xae!9\xed\xa7\x13\x98\xba0\x95<"\x9d\xab\\\xb6\x80-\xf6'],
        ['', b'<\xe8\x9e\xe9\x8a\x14\x91\x9a\xf1\xa4r=\xd2b#\x0c\x046\xf0\xa0PQ\\\x988B\x8dv\xe3b \\\xf5\x87y\xe2\xc6\xc60\x1f\xac|\x17\xe7\xa9\x8a\xab\xd6\x1a\xf0\x85`o\xec=o)\x92\xe4\xd7\x93i\xa1\x8a'],
        ['a', b'\xda\xf7\xbd\xdf(\x98q$\x96\xf8\xb5vc\xa5\xf4c\x1ez1P5^\xb6i\x8c\x95\xa3\xab\x7f\xd6\x8c@\xff\xedo\xe9\x0f\xbf;\xd7?Dc\xc7\xa5\xc7h\xa7Y\x8a\xeb\xf3\x9f\x187\xb8MC\xdc\xbd\xfc\xf7.u'],
        ['very long string of data that is supposed to be hashed, this should be longer than the hash itself', b'w?S\x97\x80\x1bP\xa6B\xc3\x9d\xd4\xad\xb70\x12Hk\x82\x07\x8f0R\x14\xffb2\x92\x8eR\x10\xd8\x8cR\xff\x8f"\xa6\xab\x96n\x1c\xc8"\xfb\x04\xe6D~\x94\xd4\x1c\n\x90\xe86\t\xce\xcd\x1dPX\x83\xe1']
    ]

    TESTDATA_HMACS = [
        ['some test data!', b'Ao~\n\xc9\x00>\x93\xbf\xa3Y\xe68\x06&X\xe5\xf3\x1ct;\x1elsA\x80\xfa\xf3\xc5\xeb#>\x1b{}\xac\xe8\x81\x1f>\tN\x9f\x8d\xa4d\xe6\x0c\xcd\xdb\x00v\xec+\xcf\xd0\x8f8d\xa6\xb2\xb9\xaa\x17'],
        ['different test data@@', b'\xd9\x817\xcc\xb0\xa2\xaeM\xc6f\xf1\x8eP\xe4\x1ar\xd7-\x13\x8f,q\xd3\xcc\xe9%\x10"\xd4:\xcb\x82\xea\xfdE\xb0J\xdaIGQ\x13rc\xe6{\xc5J\xb1\x12J\x89&\xf6B\xac\xe2\xe6\xf1\x8e\xb9\xacJS'],
        ['example password##', b'\xaa\xda{\xff\x13l\xc1\xbb\x85>t\xa5\x9bB\xcf\xab\xf2\xf7[*\x08\x8cB\xa0k@\xb1\x99\xfe)\xe4\x1d\xffA\\\x9dJd\xce\xfd\xbf;H\x07lkB\xf5\\\xca\x18na\x98\xa3\xe0r\xe4/\x11!\xc2d\x12'],
        ['', b';U\x10\xd5^\xd7Z\xaaN\xd4\x14\xa4\xdfG\xb5K9,\xa7\xd3|\x0f\x97\x81\xac\xd4\xccj8\xb5n\x85\xfb\xe7%J\xd6\xbe\xe0\xa7r\xa1\xfcb\xd3I5\xd0\xcc:1\xf2d\xb8\xe8\xd9\xf2\xdb\xad#\xb8\xe2\x18U'],
        ['bdc', b"\x8e\x94\xd0K\xe3\x17\xb3\xf2\xd25\xf3{\x98\xb3\xfc/1m\x84k>(>\xe1\xc2n\xe0\xa4*\xf7\xe5\xd8\x971\xd0\xb8gm\xc4e\xcb`\x98\xf5o\xee\xc2t\x07\x05$R'\x84\xb1PN|\xc0a\xf8\x1c\x85*"],
        ['very long string of data that is supposed to be hashed and/or encrypted, this should be longer than the hash itself', b"\xdfH\x06\x82&CSx\xaf\xd7`#\xea\xf1\xa3\xa0]fC\x0f\xc1N\x1f\xb1\x14\xd7b;\x98'\xdfz\xa0]\x89\x9f\xc5a\xc3x\xc2o\xd34,\x06\x848B\xb2\xa5;\x08h\xf1!\xd1\xe4Q2\xa1\xda\xb1\x93"]
    ]

    TESTDATA_ENCRYPT_AES = [
        'first example message or password',
        'another string of data', 
        '',
        'yeah this is a test',
        'qwe!@#',
    ]

    SALT = b'\xf4`9\x8b\xc2V\xb8\x99,\xb0\xfaK+1\xb3v'
    KEY = b'`f\x97\xaf~\x1e\x90\xd2x\x8d\xde\xaf\x19\xef\xa8\xfb}\x1e\xab\x96\x84\x7fW\xc2\xee\xd5\x0c\xc3)\\9c'

    def test_secure_data_hash_check_if_hashes_are_correct(self):
        for testdata in self.TESTDATA_HASHES:
            byte_data = testdata[0].encode('ASCII')
            original_data = testdata[1]
            hashed_data = datasec.secure_data_hash(byte_data, self.SALT)[0]
            self.assertEqual(hashed_data, original_data, msg='Error while comparing hash of "{0}"'.format(original_data))

    def test_secure_data_hash_check_if_throws_on_wrong_data_type(self):
        test_data_string = 'this is a string'
        test_data_int = 123

        with self.assertRaises(TypeError):
            datasec.secure_data_hash(test_data_string)
            datasec.secure_data_hash(test_data_int)
            datasec.secure_data_hash(b'qwe', test_data_int)
            datasec.secure_data_hash(b'123', test_data_string)

    def test_secure_data_hmac(self):
        for testdata in self.TESTDATA_HMACS:
            byte_data = testdata[0].encode('ASCII')
            original_data = testdata[1]
            hmac_data = datasec.secure_data_hmac(byte_data, self.KEY)
            self.assertEqual(hmac_data, original_data, msg='Error while comparing HMAC of "{0}"'.format(original_data))

    def test_secure_data_hmac_check_if_throws_on_wrong_data_type(self):
        test_data_string = 'this is a string'
        test_data_int = 123

        with self.assertRaises(TypeError):
            datasec.secure_data_hmac(test_data_string, self.KEY)
            datasec.secure_data_hmac(test_data_int, self.KEY)
            datasec.secure_data_hmac(b'qwe', test_data_string)
            datasec.secure_data_hmac(b'123', test_data_int)

    def test_encrypt_decrypt_data_aes(self):
        for testdata in self.TESTDATA_ENCRYPT_AES:
            original_data = testdata
            byte_original_data = original_data.encode('ASCII')
            byte_encrypted_data = datasec.encrypt_data_aes(byte_original_data, self.KEY)
            byte_decrypted_data = datasec.decrypt_data_aes(byte_encrypted_data, self.KEY)
            self.assertEqual(byte_original_data, byte_decrypted_data, msg='Failed when decrypting "{0}"'.format(original_data))

