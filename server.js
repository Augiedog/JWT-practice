require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')

const userRoutes = require('./controllers/User')

const app = express()

// Middleware
app.use(express.json())

// Routes
app.use('/user', userRoutes)

// DB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true})
    .then(() => console.log('DB connected'))
    .catch(err => console.error(err));

const PORT = process.env.PORT
app.listen(PORT, console.log('Serving it up at', PORT)
)