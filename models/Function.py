from datab import db


class Function(db.Model):
    __tablename__ = 'functions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)

    @classmethod
    def get_function_by_name(cls, name):
        function = cls.query.filter_by(name=name).first()
        if function:
            return function
        else:
            return None

    @classmethod
    def get_all_functions(cls):
        return cls.query.all()

    @classmethod
    def delete_all_functions(cls):
        functions = cls.query.all()
        for function in functions:
            db.session.delete(function)
        db.session.commit()


def create_function(name):
    function = Function(name=name)
    db.session.add(function)
    db.session.commit()
    return function
def delete_function(name):
    f =Function.get_function_by_name(name)
    db.session.delete(f)
    db.session.commit()



