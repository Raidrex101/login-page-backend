const express = require('express')
const { Pool } = require('pg')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')
require('dotenv').config()

const app = express()
const port = process.env.PORT || 5000


app.use(express.json())
app.use(cors())


const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
})


app.post('/register', async (req, res) => {
  
  const { name, email, password } = req.body
  
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email])
  
  if (result.rows.length > 0) {
    return res.status(400).json({ message: 'Email already exists' })
  }

  // Encriptar la contraseña
  const hashedPassword = await bcrypt.hash(password, 10)

  const newUser = await pool.query(
    'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
    [name, email, hashedPassword]
  )

  res.status(201).json({
    message: 'User registered successfully',
    user: newUser.rows[0]
  })
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email])

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Incorrect email or password' })
    }

    const user = result.rows[0]
    const validPassword = await bcrypt.compare(password, user.password)

    if (!validPassword) {
      return res.status(400).json({ message: 'Incorrect email or password' })
    }

   
    try {
      const now = new Date()
      const updateResult = await pool.query(
        'UPDATE users SET last_login = $1 WHERE id = $2 RETURNING last_login',
        [now, user.id]
      )

     
      if (updateResult.rows.length > 0) {
        console.log('last_login updated to:', updateResult.rows[0].last_login)
      } else {
        console.log('No se actualizaron filas para last_login')
      }

    } catch (error) {
      console.error('Error updating last_login:', error)
      return res.status(500).json({ message: 'Error updating login time' })
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' })
    res.json({ message: 'Login successful', token })
  } catch (error) {
    console.error('Error during login:', error)
    res.status(500).json({ message: 'Server error', error: error.message })
  }
})

const authenticate = (req, res, next) => {
  const token = req.header('x-auth-token')
  
  if (!token) {
    return res.status(401).json({ message: 'Forbidden' })
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = decoded
    next()
  } catch (err) {
    return res.status(400).json({ message: 'Invalid token' })
  }
}

app.get('/users', authenticate, async (req, res) => {
  const users = await pool.query('SELECT id, name, email, status, last_login FROM users')
  res.json(users.rows)
})
app.get('/', (req, res) => {
  res.send('Backend is working!')
})

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
