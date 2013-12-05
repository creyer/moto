import boto
import sure  # noqa
from freezegun import freeze_time

from moto import mock_dynamodb2

from boto.dynamodb2.fields import HashKey
from boto.dynamodb2.fields import RangeKey
from boto.dynamodb2.table import Table
from boto.dynamodb2.table import Item

from boto.dynamodb.exceptions import DynamoDBKeyNotFoundError
from boto.dynamodb2.exceptions import ValidationException
from boto.dynamodb2.exceptions import ConditionalCheckFailedException
from boto.exception import DynamoDBResponseError


def create_table():
    table = Table.create('messages', schema=[
        HashKey('forum_name'),
        RangeKey('subject'),
    ], throughput={
        'read': 10,
        'write': 10,
    })
    return table

@freeze_time("2012-01-14")
@mock_dynamodb2
def test_create_table():
    table = create_table()
    expected = {
        'Table': {
            'AttributeDefinitions': [
                {'AttributeName': 'forum_name', 'AttributeType': 'S'}, 
                {'AttributeName': 'subject', 'AttributeType': 'S'}
            ], 
            'ProvisionedThroughput': {
                'NumberOfDecreasesToday': 0, 'WriteCapacityUnits': 10, 'ReadCapacityUnits': 10
                }, 
            'TableSizeBytes': 0, 
            'TableName': 'messages', 
            'TableStatus': 'ACTIVE', 
            'KeySchema': [
                {'KeyType': 'HASH', 'AttributeName': 'forum_name'}, 
                {'KeyType': 'RANGE', 'AttributeName': 'subject'}
            ], 
            'ItemCount': 0, 'CreationDateTime': 1326499200.0
        }
    }
    table.describe().should.equal(expected)

@mock_dynamodb2
def test_delete_table():
    conn = boto.connect_dynamodb()
    table = create_table()
    conn.list_tables().should.have.length_of(1)

    table.delete()
    conn.list_tables().should.have.length_of(0)

    conn.layer1.delete_table.when.called_with('messages').should.throw(DynamoDBResponseError)


@mock_dynamodb2
def test_update_table_throughput():
    table = create_table()
    print table.throughput
    table.throughput["read"].should.equal(10)
    table.throughput["write"].should.equal(10)    
    table.update(throughput={
        'read': 5,
        'write': 15,
     })
    
    
    table.throughput["read"].should.equal(5)
    table.throughput["write"].should.equal(15)

    
    table.update(throughput={
        'read': 5,
        'write': 6,
     })
    
    table.describe()

    table.throughput["read"].should.equal(5)
    table.throughput["write"].should.equal(6)
    

@mock_dynamodb2
def test_item_add_and_describe_and_update():
    conn = boto.connect_dynamodb()
    table = create_table()
    ok = table.put_item(data={
        'forum_name': 'LOLCat Forum',
        'subject': 'Check this out!',
        'Body': 'http://url_to_lolcat.gif',
        'SentBy': 'User A',
        'ReceivedTime': '12/9/2011 11:36:03 PM',
     })
    ok.should.equal(True)
    
    table.get_item(forum_name="LOLCat Forum",subject='Check this out!').should_not.be.none

    returned_item = table.get_item(
        forum_name='LOLCat Forum',
        subject='Check this out!'
    )
    dict(returned_item).should.equal({
        'forum_name': 'LOLCat Forum',
        'subject': 'Check this out!',
        'Body': 'http://url_to_lolcat.gif',
        'SentBy': 'User A',
        'ReceivedTime': '12/9/2011 11:36:03 PM',
    })

    
    returned_item['SentBy'] = 'User B'
    returned_item.save(overwrite=True)

    returned_item = table.get_item(
        forum_name='LOLCat Forum',
        subject='Check this out!'
    )
    dict(returned_item).should.equal({
        'forum_name': 'LOLCat Forum',
        'subject': 'Check this out!',
        'Body': 'http://url_to_lolcat.gif',
        'SentBy': 'User B',
        'ReceivedTime': '12/9/2011 11:36:03 PM',
    })
    

@mock_dynamodb2
def test_item_put_without_table():
    conn = boto.connect_dynamodb()

    conn.layer1.put_item.when.called_with(
        table_name='undeclared-table',
        item=dict(
            hash_key='LOLCat Forum',
            range_key='Check this out!'
        ),
    ).should.throw(DynamoDBResponseError)


@mock_dynamodb2
def test_get_missing_item():
    conn = boto.connect_dynamodb()
    table = create_table()

    table.get_item.when.called_with(
        hash_key='tester',
        range_key='other',
    ).should.throw(ValidationException)
    


@mock_dynamodb2
def test_get_item_with_undeclared_table():
    conn = boto.connect_dynamodb()

    conn.layer1.get_item.when.called_with(
        table_name='undeclared-table',
        key={
            'HashKeyElement': {'S': 'tester'},
            'RangeKeyElement': {'S': 'test-range'},
        },
    ).should.throw(DynamoDBKeyNotFoundError)


@mock_dynamodb2
def test_get_item_without_range_key():
    table = Table.create('messages', schema=[
        HashKey('test_hash'),
        RangeKey('test_range'),
    ], throughput={
        'read': 10,
        'write': 10,
    })
    
    hash_key = 3241526475
    range_key = 1234567890987
    table.put_item( data = {'test_hash':hash_key, 'test_range':range_key})

    table.get_item.when.called_with(test_hash=hash_key).should.throw(ValidationException)


@mock_dynamodb2
def test_delete_item():
    table = create_table()
    item_data = {
        'forum_name': 'LOLCat Forum',
        'Body': 'http://url_to_lolcat.gif',
        'SentBy': 'User A',
        'ReceivedTime': '12/9/2011 11:36:03 PM',
    }
    item =Item(table,item_data)
    item['subject'] = 'Check this out!'        
    item.save()
    table.count().should.equal(1)

    response = item.delete()
    response.should.equal(True)
    
    table.count().should.equal(0)
    item.delete.when.called_with().should.throw(ConditionalCheckFailedException)




@mock_dynamodb2
def test_delete_item_with_undeclared_table():
    conn = boto.connect_dynamodb()

    conn.layer1.delete_item.when.called_with(
        table_name='undeclared-table',
        key={
            'HashKeyElement': {'S': 'tester'},
            'RangeKeyElement': {'S': 'test-range'},
        },
    ).should.throw(DynamoDBResponseError)

@mock_dynamodb2
def test_query():

    table = create_table()

    item_data = {
        'forum_name': 'LOLCat Forum',
        'Body': 'http://url_to_lolcat.gif',
        'SentBy': 'User A',
        'ReceivedTime': '12/9/2011 11:36:03 PM',
        'subject': 'Check this out!' 
    }
    item =Item(table,item_data)     
    item.save(overwrite=True)
    
    item['forum_name'] = 'the-key'
    item['subject'] = '456'
    item.save(overwrite=True)

    item['forum_name'] = 'the-key'
    item['subject'] = '123'
    item.save(overwrite=True)
    
    item['forum_name'] = 'the-key'
    item['subject'] = '789'
    item.save(overwrite=True)

    table.count().should.equal(4)

    results = table.query(forum_name__eq='the-key', subject__gt='1',consistent=True)
    results.should.have.length_of(3)

    """results = table.query(hash_key='the-key', range_key_condition=condition.GT('234'))
    results.response['Items'].should.have.length_of(2)

    results = table.query(hash_key='the-key', range_key_condition=condition.GT('9999'))
    results.response['Items'].should.have.length_of(0)

    results = table.query(hash_key='the-key', range_key_condition=condition.CONTAINS('12'))
    results.response['Items'].should.have.length_of(1)

    results = table.query(hash_key='the-key', range_key_condition=condition.BEGINS_WITH('7'))
    results.response['Items'].should.have.length_of(1)

    results = table.query(hash_key='the-key', range_key_condition=condition.BETWEEN('567', '890'))
    results.response['Items'].should.have.length_of(1)
"""
"""
@mock_dynamodb
def test_query_with_undeclared_table():
    conn = boto.connect_dynamodb()

    conn.layer1.query.when.called_with(
        table_name='undeclared-table',
        hash_key_value={'S': 'the-key'},
        range_key_conditions={
            "AttributeValueList": [{
                "S": "User B"
            }],
            "ComparisonOperator": "EQ",
        },
    ).should.throw(DynamoDBResponseError)


@mock_dynamodb
def test_scan():
    conn = boto.connect_dynamodb()
    table = create_table(conn)

    item_data = {
        'Body': 'http://url_to_lolcat.gif',
        'SentBy': 'User A',
        'ReceivedTime': '12/9/2011 11:36:03 PM',
    }
    item = table.new_item(
        hash_key='the-key',
        range_key='456',
        attrs=item_data,
    )
    item.put()

    item = table.new_item(
        hash_key='the-key',
        range_key='123',
        attrs=item_data,
    )
    item.put()

    item_data = {
        'Body': 'http://url_to_lolcat.gif',
        'SentBy': 'User B',
        'ReceivedTime': '12/9/2011 11:36:03 PM',
        'Ids': set([1, 2, 3]),
        'PK': 7,
    }
    item = table.new_item(
        hash_key='the-key',
        range_key='789',
        attrs=item_data,
    )
    item.put()

    results = table.scan()
    results.response['Items'].should.have.length_of(3)

    results = table.scan(scan_filter={'SentBy': condition.EQ('User B')})
    results.response['Items'].should.have.length_of(1)

    results = table.scan(scan_filter={'Body': condition.BEGINS_WITH('http')})
    results.response['Items'].should.have.length_of(3)

    results = table.scan(scan_filter={'Ids': condition.CONTAINS(2)})
    results.response['Items'].should.have.length_of(1)

    results = table.scan(scan_filter={'Ids': condition.NOT_NULL()})
    results.response['Items'].should.have.length_of(1)

    results = table.scan(scan_filter={'Ids': condition.NULL()})
    results.response['Items'].should.have.length_of(2)

    results = table.scan(scan_filter={'PK': condition.BETWEEN(8, 9)})
    results.response['Items'].should.have.length_of(0)

    results = table.scan(scan_filter={'PK': condition.BETWEEN(5, 8)})
    results.response['Items'].should.have.length_of(1)


@mock_dynamodb
def test_scan_with_undeclared_table():
    conn = boto.connect_dynamodb()

    conn.layer1.scan.when.called_with(
        table_name='undeclared-table',
        scan_filter={
            "SentBy": {
                "AttributeValueList": [{
                    "S": "User B"}
                ],
                "ComparisonOperator": "EQ"
            }
        },
    ).should.throw(DynamoDBResponseError)


@mock_dynamodb
def test_write_batch():
    conn = boto.connect_dynamodb()
    table = create_table(conn)

    batch_list = conn.new_batch_write_list()

    items = []
    items.append(table.new_item(
        hash_key='the-key',
        range_key='123',
        attrs={
            'Body': 'http://url_to_lolcat.gif',
            'SentBy': 'User A',
            'ReceivedTime': '12/9/2011 11:36:03 PM',
        },
    ))

    items.append(table.new_item(
        hash_key='the-key',
        range_key='789',
        attrs={
            'Body': 'http://url_to_lolcat.gif',
            'SentBy': 'User B',
            'ReceivedTime': '12/9/2011 11:36:03 PM',
            'Ids': set([1, 2, 3]),
            'PK': 7,
        },
    ))

    batch_list.add_batch(table, puts=items)
    conn.batch_write_item(batch_list)

    table.refresh()
    table.item_count.should.equal(2)

    batch_list = conn.new_batch_write_list()
    batch_list.add_batch(table, deletes=[('the-key', '789')])
    conn.batch_write_item(batch_list)

    table.refresh()
    table.item_count.should.equal(1)


@mock_dynamodb
def test_batch_read():
    conn = boto.connect_dynamodb()
    table = create_table(conn)

    item_data = {
        'Body': 'http://url_to_lolcat.gif',
        'SentBy': 'User A',
        'ReceivedTime': '12/9/2011 11:36:03 PM',
    }
    item = table.new_item(
        hash_key='the-key',
        range_key='456',
        attrs=item_data,
    )
    item.put()

    item = table.new_item(
        hash_key='the-key',
        range_key='123',
        attrs=item_data,
    )
    item.put()

    item_data = {
        'Body': 'http://url_to_lolcat.gif',
        'SentBy': 'User B',
        'ReceivedTime': '12/9/2011 11:36:03 PM',
        'Ids': set([1, 2, 3]),
        'PK': 7,
    }
    item = table.new_item(
        hash_key='another-key',
        range_key='789',
        attrs=item_data,
    )
    item.put()

    items = table.batch_get_item([('the-key', '123'), ('another-key', '789')])
    # Iterate through so that batch_item gets called
    count = len([x for x in items])
    count.should.equal(2)
"""

"""
new method to test-----get_key_fields

users.get_item(**{
...     'date-joined': 127549192,
... }
"""