from flask import Flask, abort, request, render_template,render_template_string
import random
import string

app = Flask(__name__)


def generate_password(length, lower=False, upper=False, numbers=False, symbols=False):
    low = string.ascii_lowercase if lower else ''
    upp = string.ascii_uppercase if upper else ''
    num = string.digits if numbers else ''
    symb = string.punctuation if symbols else ''
    
    passw = low + upp + num + symb

    if not passw:
        return None
    

    password = ''.join(random.choice(passw) for _ in range(length))
    return password


@app.route('/')
def home():
    return render_template('index.html')
    

@app.route('/generate-password-form', methods=['POST'])
def get_password():
    length = int(request.form.get('length'))
    lower = 'lower' in request.form
    upper = 'upper' in request.form
    numbers = 'numbers' in request.form
    symbols = 'symbols' in request.form
    
    
    password = generate_password(length, lower, upper, numbers,symbols)

    if password is None:
        abort(400, description="Error: No character set selected to generate password.")
    
    
    return render_template('generated.html',password=password)
    
    

if __name__ == '__main__':
    app.run()
