from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

class IPAddressForm(FlaskForm):
    ip_address = StringField('IP Address', validators=[DataRequired()])
    prefix_length = StringField('Prefix Length', validators=[DataRequired()])
    submit = SubmitField('add IP address to netbox')