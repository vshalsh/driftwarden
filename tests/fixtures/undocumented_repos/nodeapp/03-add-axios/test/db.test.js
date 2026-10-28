const { Client } = require('pg');

test('db', () => expect(Client).toBeDefined());
