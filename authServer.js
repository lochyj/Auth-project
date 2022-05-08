require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const mongo = require('mongodb').MongoClient
const bcrypt = require('bcrypt')
const url = 'mongodb://localhost:27017/'
const dbName = 'auth'

app.use(express.json())

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

let refreshTokens = []
let users = []

updateUsers()

console.log(users)

app.post('/register', async(req, res) => {
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

app.post('/token', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken })
    })
})

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

app.post('/login', async(req, res) => {
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

app.listen(4000)