from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    Optional
)

class SignupForm(FlaskForm):
    """User Sign-up Form."""
    username = StringField(
        'username',
        validators=[

            Length(min=3, max=20),
            DataRequired()
                    ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=6, message='Select a stronger password.')
        ]
    )


class LoginForm(FlaskForm):
    """User Log-in Form."""
    username = StringField(
        'username',
        validators=[
            DataRequired()
        ]
    )
    password = PasswordField('Password', validators=[DataRequired()])
    #submit = SubmitField('Log In')


