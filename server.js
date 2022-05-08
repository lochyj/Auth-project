require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const mongo = require('mongodb').MongoClient
const bcrypt = require('bcrypt')
const url = 'mongodb://localhost:27017/'
const dbName = 'auth'

app.use(express.json())
app.use(express.static('./src/pages/'))


app.get('/app', authenticateToken, (req, res) => {
    res.sendFile('./src/secure/index.html', { root: __dirname })
})

app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name))
})

const posts = [{
        username: 'Kyle',
        title: 'Post 1'
    },
    {
        username: 'Jim',
        title: 'Post 2'
    }
]

let refreshTokens = []
let users = []
updateUsers()
app.post('/auth/register', async(req, res) => {
    // check if the username and password are in a json format and if not make them so
    if (!req.body.username || !req.body.password) {
        res.status(400).json({
            message: 'Please provide a username and password'
        })
        return
    }
    const { username, password } = req.body
        // check if the username is in the database
    const user = users.find(user => user.username === username)
    if (user) {
        res.status(400).json({ error: 'Username already exists' })
    } else {
        // if not, create a new user
        const hash = await bcrypt.hash(password, 10)
        store(username, hash)
        res.status(200).json({ message: 'User created' })
    }
    updateUsers()
})
app.post('/auth/token', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken })
    })
})
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
            res.json({ accessToken: accessToken, refreshToken: refreshToken })
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
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user
        next()
    })
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
app.listen(80)
