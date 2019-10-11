from peewee import *


db = SqliteDatabase('db/db/database.db', pragmas={'foreign_keys': 1})


class BaseModel(Model):
    class Meta:
        database = db


class User(BaseModel):
    username = CharField(unique=True)
    password = CharField()


class Invitation(BaseModel):
    inviter = ForeignKeyField(User, on_delete='CASCADE')
    invitee = ForeignKeyField(User, on_delete='CASCADE')


class Friend(BaseModel):
    user = ForeignKeyField(User, on_delete='CASCADE')
    friend = ForeignKeyField(User, on_delete='CASCADE')


class Post(BaseModel):
    user = ForeignKeyField(User, on_delete='CASCADE')
    message = CharField()


class Token(BaseModel):
    token = CharField(unique=True)
    owner = ForeignKeyField(User, on_delete='CASCADE')
    channel = CharField(unique=True)


class Group(BaseModel):
    name = CharField(unique=True)
    channel = CharField(unique=True)


class GroupMember(BaseModel):
    group = ForeignKeyField(Group, on_delete='CASCADE')
    member = ForeignKeyField(User, on_delete='CASCADE')


if __name__ == '__main__':
    db.connect()
    db.create_tables([User, Invitation, Friend, Post, Token, Group, GroupMember])
