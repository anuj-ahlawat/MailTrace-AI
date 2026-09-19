const appDb = db.getSiblingDB('mailtrace_enterprise');
appDb.createUser({ user: process.env.MONGO_APP_USER, pwd: process.env.MONGO_APP_PASSWORD, roles: [{ role: 'readWrite', db: 'mailtrace_enterprise' }] });
