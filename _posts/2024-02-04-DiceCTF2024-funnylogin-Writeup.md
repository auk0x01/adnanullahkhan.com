---
title: DiceCTF-2024 funnylogin (Web Challenge) Writeup
date: 2024-02-04 10:03
categories: [ctf, web]
tags: [dicectf, web, ctf]    # TAG names should be lowercase
---

So, I recently solved one web challenge from DiceCTF 2024. The name of the challenge is funnylogin. I loved the challenge as it required a little creativity.

# Challenge

We are given a login page. Looking at the source code, we see that this challenge is about SQLI.
```js
const express = require('express');
const crypto = require('crypto');

const app = express();

const db = require('better-sqlite3')('db.sqlite3');
db.exec(`DROP TABLE IF EXISTS users;`);
db.exec(`CREATE TABLE users(
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT
);`);

const FLAG = process.env.FLAG || "dice{test_flag}";
const PORT = process.env.PORT || 3000;

const users = [...Array(100_000)].map(() => ({ user: `user-${crypto.randomUUID()}`, pass: crypto.randomBytes(8).toString("hex") }));
db.exec(`INSERT INTO users (id, username, password) VALUES ${users.map((u,i) => `(${i}, '${u.user}', '${u.pass}')`).join(", ")}`);

const isAdmin = {};
const newAdmin = users[Math.floor(Math.random() * users.length)];
isAdmin[newAdmin.user] = true;

app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

app.post("/api/login", (req, res) => {
    const { user, pass } = req.body;

    const query = `SELECT id FROM users WHERE username = '${user}' AND password = '${pass}';`;
    try {
        const id = db.prepare(query).get()?.id;
        if (!id) {
            return res.redirect("/?message=Incorrect username or password");
        }

        if (users[id] && isAdmin[user]) {
            return res.redirect("/?flag=" + encodeURIComponent(FLAG));
        }
        return res.redirect("/?message=This system is currently only available to admins...");
    }
    catch {
        return res.redirect("/?message=Nice try...");
    }
});

app.listen(PORT, () => console.log(`web/funnylogin listening on port ${PORT}`));
```

First, application is generating 100,000 records of randomly-generated UUID and password. Then these values are being inserted into database. There is another column named "id" being inserted in the database. This "id" column is not random and is just an incrementation value of all records like "1,2,3,4....n".

This query is simple and is vulnerable to SQLI attacks and can easily by exploited.
```js
const query = `SELECT id FROM users WHERE username = '${user}' AND password = '${pass}';`;
```
But right after this code, we have this:
```js
        const id = db.prepare(query).get()?.id;
        if (!id) {
            return res.redirect("/?message=Incorrect username or password");
        }
```
It is basically checking if it gets any valid "id" present in the database. So basically, our goal is to make the DB query return some "id" present in the database.
We can inject ```' OR id=1-- -``` in username field to see what happens because as I said earlier, the ids are not "random". They are just incremented numbers ranging 1-100000.
Injecting this username field, now we get different response.

![img](https://i.imgur.com/dbrgwWx.jpeg)

We bypassed this piece of code. 
```js
    const query = `SELECT id FROM users WHERE username = '${user}' AND password = '${pass}';`;
    try {
        const id = db.prepare(query).get()?.id;
        if (!id) {
            return res.redirect("/?message=Incorrect username or password");
        }
```

It was checking the "id" and after our injected query which was returning "id", this condition returned false and did not return bypassing this check. 

Coming to the second obstacle. We see:
```js
        if (users[id] && isAdmin[user]) {
            return res.redirect("/?flag=" + encodeURIComponent(FLAG));
        }
        return res.redirect("/?message=This system is currently only available to admins...");
```

So, we will also have to make these 2 conditions true in order to get the flag. 1st condition will automatically be true when we make our query return some valid "id". 2nd condition is quite interesting.

Let's see how application handled admin functionality in the initial code.
```js
const isAdmin = {};
const newAdmin = users[Math.floor(Math.random() * users.length)];
isAdmin[newAdmin.user] = true;
```

Here, en empty object "isAdmin" is being created. Then a randomly selected user object will be stored in newAdmin from the users array. Later, a new property is created in the isAdmin object with a key being the username of the randomly selected user object and its value being true.
"username" will be used as a property name here to check if that specific type of user is admin or not.
```js
        if (users[id] && isAdmin[user]) {
            return res.redirect("/?flag=" + encodeURIComponent(FLAG));
        }
        return res.redirect("/?message=This system is currently only available to admins...");
```
If we try to return non-existing properties on an Object, it returns false. Now here's a catch, If an Object has ```__proto__``` property, then checking this in boolean context returns true.
So, if ```Object[__proto__]``` returns true, then final payload can be crafted like this:
```
SELECT id FROM users WHERE username = '__proto__' AND password = '' OR id=1-- -';
```

Entering both, we got the flag.
![img](https://i.imgur.com/wip7IuY.jpeg)


Thankyou for Reading
