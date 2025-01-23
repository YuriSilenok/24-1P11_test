from peewee import SqliteDatabase, Model, CharField, BooleanField


db = SqliteDatabase("test.db")


class Table(Model):
    class Meta:
        database = db


class User(Table):
    username = CharField()
    full_name = CharField()
    email = CharField()
    hashed_password = CharField()
    disabled = BooleanField()

s
if __name__ == "__main__":
    with db:
        db.create_tables([User])

