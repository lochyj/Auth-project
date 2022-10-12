require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const mongo = require('mongodb').MongoClient
const bcrypt = require('bcrypt')
var cookieParser = require('cookie-parser')
const url = 'mongodb://127.0.0.1:27017/'
const dbName = 'auth'
app.use(express.json())
app.use(cookieParser())


// PUBLIC PAGES
app.get('/', (req, res) => {
    res.sendFile('./src/index.html', { root: __dirname })
})
app.get('/register', (req, res) => {
    res.sendFile('./src/register.html', { root: __dirname })
})
app.get('/login', (req, res) => {
    res.sendFile('./src/login.html', { root: __dirname })
})

// SECURE PAGE
app.get('/app', authenticateToken, (req, res) => { /* Add authenticateToken to make the route secure */
    res.sendFile('./src/app.html', { root: __dirname })
})

// SECURE API
// TODO: fix this
app.get('/api/users/data', authenticateToken, (req, res) => {
    const user = getUser(req.cookies.accessToken);
    if (user == null) {
        res.sendStatus(403)
    } else {
        // fix this
        console.log(getUserData(user))
        res.status(200).json(getUserData(user));
    }
})

// TODO: Make this
app.post('/api/post/create', authenticateToken, (req, res) => {
    const user = getUser(req.cookies.accessToken);
    try {
        createPost(user, req.body)
        res.sendStatus(200)
    } catch (err) {
        res.sendStatus(400)
    }
})

// IGNORE ALL BELOW
// -------------------

let refreshTokens = []
let users = []
updateUsers()
app.post('/auth/register', async(req, res) => {
    if (!req.body.username || !req.body.password) {
        res.status(400).json({
            message: 'Please provide a username and password'
        })
        return
    }
    const { username, password } = req.body
    const user = users.find(user => user.username === username)
    if (user) {
        res.status(400).json({ error: 'Username already exists' })
    } else {
        const hash = await bcrypt.hash(password, 10)
        store(username, hash)
        updateUsers()
        res.status(200).json({ message: 'User created' })
    }
})
app.post('/auth/token', (req, res) => {

    // Getting the refresh token from the requests http only cookies
    const refreshToken = req.body.token

    // If there is no refresh token in the request return an error && If the refresh token does not exist in our array of refresh tokens return an error
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)

    // Verify the refresh token, if it is valid, respond with an access token, otherwise return an error
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        // If there was a server side error return an error
        if (err) return res.sendStatus(403)

        // If the refresh token is valid create a new access token, and send it to the user
        const accessToken = generateAccessToken({ name: user.name })
        res.cookie('accessToken', accessToken, { httpOnly: true, overwrite: true })
    })
})

// Delete the refresh token from the array of refresh tokens
app.delete('/auth/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

app.post('/auth/login', async(req, res) => {
    const username = req.body.username
    const user = users.find(user => user.username === username)
    if (user) {
        const password = req.body.password
        const hash = user.password
        const isValid = await bcrypt.compare(password, hash)
        if (isValid) {
            const accessToken = generateAccessToken({ name: user.username })
            const refreshToken = jwt.sign({ name: user.username }, process.env.REFRESH_TOKEN_SECRET)
            refreshTokens.push(refreshToken)
            res.cookie('accessToken', accessToken, { httpOnly: true })
            res.cookie('refreshToken', refreshToken, { httpOnly: true })
            res.send().status(200)
        } else {
            res.status(400).json({ error: 'Invalid credentials' })
        }
    } else {
        res.status(400).json({ error: 'User does not exist' })
    }
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_TIME })
}

function authenticateToken(req, res, next) {
    const token = req.cookies.accessToken;

    // If there is no token in the request return an error and redirect to login
    if (token == null) return res.sendStatus(401).redirect('/login');

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user;
        next()
    })
}

function getUser(token) {
    let User;
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return null;
        User = user;
    })
    return User.name;
}

function store(username, password) {
    mongo.connect(url, (err, client) => {
        if (err) {
            console.log(err)
        }
        const db = client.db(dbName)
        const collection = db.collection('users')
        collection.insertOne({ username: username, password: password }, (err, result) => {
            if (err) {
                console.log(err)
            }
            client.close()
        })
    })
}

function updateUsers() {
    mongo.connect(url, (err, client) => {
        if (err) {
            console.log(err)
        }
        const db = client.db(dbName)
        const collection = db.collection('users')
        collection.find({}).toArray((err, result) => {
            if (err) {
                console.log(err)
            }
            users = result
            client.close()
        })
    })
}

function createPost(username, data) {
    mongo.connect(url, (err, client) => {
        if (err) {
            console.log(err)
        }
        const db = client.db(dbName)
        const collection = db.collection('data')
        // check if the user allready has posts and append on to the end
        collection.find({ username: username }).toArray((err, result) => {
            if (err) {
                console.log(err)
            }
            if (result.length == 0) {
                collection.insertOne({ username: username, posts: [{ title: data.title, content: data.content }] }, (err, result) => {
                    if (err) {
                        console.log(err)
                    }
                    client.close()
                })
        
            } else {
                collection.updateOne({ username: username }, { $push: { posts: { title: 'test', content: 'test' } } }, (err, result) => {
                    if (err) {
                        console.log(err)
                    }
                    client.close()
                })
            }
        })
    })
}

function getUserData(user) {
    let Result;
    mongo.connect(url, (err, client) => {
        if (err) {
            console.log(err)
        }
        const db = client.db(dbName)
        const collection = db.collection('data')
        collection.find({ username: user }).toArray((err, result) => {
            if (err) {
                console.log(err)
            }
            Result = result
            console.log(Result)
            client.close()
        })
    })
    return Result;
};
app.listen(80)