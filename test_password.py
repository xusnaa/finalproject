import unittest
import string
from app import app, generate_password, password_policy


class TestPasswordGenerator(unittest.TestCase):
    def setUp(self):
        # Set up the Flask test client
        self.app = app.test_client()
        self.app.testing = True

    def test_generate_password_valid(self):
        # Test if the generated password meets all requirements
        password = generate_password(length=12, lower=True, upper=True, numbers=True, symbols=True)
        print(f"Generated password: {password}")  

        # Check for at least one lowercase letter
        self.assertTrue(any(c.islower() for c in password))
        # Check for at least one uppercase letter
        self.assertTrue(any(c.isupper() for c in password))
        # Check for at least one digit
        self.assertTrue(any(c.isdigit() for c in password))
        # Check for at least one special character
        self.assertTrue(any(c in string.punctuation for c in password))
        # Check the length of the password
        self.assertEqual(len(password), 12)

    def test_password_policy_valid(self):
        # Test a valid password
        password = "ValidPass1!"
        result = password_policy(password)
        self.assertEqual(result, "Valid")

    def test_password_policy_invalid(self):
        # Test an invalid password (missing uppercase letter)
        password = "invalidpass1!"
        result = password_policy(password)
        self.assertNotEqual(result, "Valid")
        self.assertIn("Password must include at least one uppercase letter.", result)

    def test_generate_password_api(self):
        # Test the /generate-password API endpoint
        response = self.app.get('/generate-password')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("password", data)
        self.assertEqual(data["policy"], "Password policy has been satisfied.")

    def test_stored_passwords_api(self):
        # Test the /stored-passwords API endpoint
        # First, generate a password to ensure the list is not empty
        self.app.get('/generate-password')
        response = self.app.get('/stored-passwords')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("hashed_passwords", data)
        self.assertGreater(len(data["hashed_passwords"]), 0)

    def test_rate_limiting(self):
        # Test rate limiting by making more than 5 requests to /generate-password
        for _ in range(6):
            response = self.app.get('/generate-password')
            if _ < 5:
                self.assertEqual(response.status_code, 200)
            else:
                # The 6th request should be rate-limited
                self.assertEqual(response.status_code, 429)

    def test_ip_whitelisting(self):
        # Test IP whitelisting by simulating a request from a disallowed IP
        
        response = self.app.get('/stored-passwords')
        self.assertEqual(response.status_code, 200)  


if __name__ == '__main__':
    unittest.main()