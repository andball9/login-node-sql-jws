const express = require('express')
const router = express.Router()

const authController = require('../controllers/authController')

// rutas vistas
router.get('/', authController.isAuthenticated, (req, res)=>{
    res.render('index')
})
router.get('/login', (req, res)=>{
    res.render('login', {alert:false})
})
router.get('/registro', (req, res)=>{
    res.render('register')
})

router.post('/register', authController.register)
router.post('/login', authController.login)
router.get('/logout', authController.logout)

module.exports = router