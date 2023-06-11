from flask import Flask
import models.Function as f

from datab import db
from app import app




with app.app_context():
    f.create_function('GETaccounts')
    f.create_function('GETmoney')
    f.create_function('GETposts')
    f.create_function('GETinside')
    f.create_function('DELETEposts')
    f.create_function('POSTxml_http')
    f.create_function('POSTemail')
    f.create_function('GETemail')
    f.create_function('POSTposts')
    f.create_function('DELETEaccounts')
    f.create_function('GETaccountslist')
    f.create_function('POSTproduct')
    f.create_function('GETstock')
    #f.create_function('GETcloses')

    db.session.commit()