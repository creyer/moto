import boto
import sure  # noqa
import requests
import boto.dynamodb2
from moto import mock_dynamodb2
from moto.dynamodb2 import dynamodb_backend2
from boto.exception import JSONResponseError


@mock_dynamodb2
def test_list_tables():
    name = 'TestTable'    
    #{'schema': }    
    dynamodb_backend2.create_table(name,schema=[
        {u'KeyType': u'HASH', u'AttributeName': u'forum_name'}, 
        {u'KeyType': u'RANGE', u'AttributeName': u'subject'}
    ])
    conn =  boto.dynamodb2.connect_to_region(
            'us-west-2',
        aws_access_key_id="ak",
        aws_secret_access_key="sk")
    assert conn.list_tables()["TableNames"] == [name]


@mock_dynamodb2
def test_list_tables_layer_1():
    dynamodb_backend2.create_table("test_1",schema=[
        {u'KeyType': u'HASH', u'AttributeName': u'name'}
    ])
    dynamodb_backend2.create_table("test_2",schema=[
        {u'KeyType': u'HASH', u'AttributeName': u'name'}
    ])
    conn =  boto.dynamodb2.connect_to_region(
        'us-west-2',
        aws_access_key_id="ak",
        aws_secret_access_key="sk")
    
    res = conn.list_tables(limit=1)
    expected = {"TableNames": ["test_1"], "LastEvaluatedTableName": "test_1"}
    res.should.equal(expected)

    res = conn.list_tables(limit=1, exclusive_start_table_name="test_1")
    expected = {"TableNames": ["test_2"]}
    res.should.equal(expected)


@mock_dynamodb2
def test_describe_missing_table():
    conn =  boto.dynamodb2.connect_to_region(
        'us-west-2',
        aws_access_key_id="ak",
        aws_secret_access_key="sk")
    conn.describe_table.when.called_with('messages').should.throw(JSONResponseError)


@mock_dynamodb2
def test_sts_handler():
    res = requests.post("https://sts.amazonaws.com/", data={"GetSessionToken": ""})
    res.ok.should.be.ok
    res.text.should.contain("SecretAccessKey")
