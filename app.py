from flask import Flask, render_template, request, flash
from cipher import UltimateCipher
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production

def validate_affine_a(form, field):
    valid_a_values = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    if field.data not in valid_a_values:
        raise ValidationError(
            'Affine key "a" must be coprime with 26. Valid values are: ' + 
            ', '.join(str(x) for x in valid_a_values)
        )

def validate_vigenere_key(form, field):
    if not field.data.isalpha():
        raise ValidationError('Vigenere key must contain only alphabetic characters')

class CipherForm(FlaskForm):
    text = StringField('Text to Process', validators=[
        DataRequired(message='Please enter text to process')
    ])
    action = SelectField(
        'Action',
        choices=[('encrypt', 'Encrypt'), ('decrypt', 'Decrypt')],
        validators=[DataRequired()]
    )
    affine_a = IntegerField(
        'Affine Key "a"',
        validators=[
            DataRequired(message='Please enter Affine key "a"'),
            NumberRange(min=1, max=25, message='Affine key "a" must be between 1 and 25'),
            validate_affine_a
        ]
    )
    affine_b = IntegerField(
        'Affine Key "b"',
        validators=[
            DataRequired(message='Please enter Affine key "b"'),
            NumberRange(min=0, max=25, message='Affine key "b" must be between 0 and 25')
        ]
    )
    vigenere_key = StringField(
        'Vigenere Key',
        validators=[
            DataRequired(message='Please enter Vigenere key'),
            validate_vigenere_key
        ]
    )
    xor_key = StringField(
        'XOR Key',
        validators=[DataRequired(message='Please enter XOR key')]
    )
    submit = SubmitField('Process')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = CipherForm()
    result = None
    original_text = None
    
    if form.validate_on_submit():
        cipher = UltimateCipher()
        try:
            original_text = form.text.data
            if form.action.data == 'encrypt':
                result = cipher.encrypt(
                    form.text.data,
                    form.affine_a.data,
                    form.affine_b.data,
                    form.vigenere_key.data,
                    form.xor_key.data
                )
                flash('Text encrypted successfully!', 'success')
            else:
                result = cipher.decrypt(
                    form.text.data,
                    form.affine_a.data,
                    form.affine_b.data,
                    form.vigenere_key.data,
                    form.xor_key.data
                )
                flash('Text decrypted successfully!', 'success')
        except ValueError as e:
            flash(str(e), 'error')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
    
    return render_template('index.html', form=form, result=result, original_text=original_text)

if __name__ == '__main__':
    app.run(debug=True) 