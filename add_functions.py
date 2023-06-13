import models.Function as f
from app import app
from datab import db

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
    a = f.Function.get_all_functions()

    #f.create_function('GETcloses')

    db.session.commit()