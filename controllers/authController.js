const jwt = require('jsonwebtoken')
const bcryptjs = require('bcryptjs')
const conexion = require('../database/db')
const{promisify} = require('util')

// registro
exports.register = async (req, res) => {
    try {
        const Nombre = req.body.Nombre
        const Usuario = req.body.Usuario
        const pass = req.body.Pass
        let passHash = await bcryptjs.hash(pass, 8)

        conexion.query('INSERT INTO users SET ?', {Nombre:Nombre, Usuario:Usuario, Pass:passHash}, (error, results)=>{
            if (error) {console.log(error)}
            res.redirect('/')
        })
    } catch (error) {
        console.log(error)
    }
}
// login
exports.login = async (req, res) => {
    try {
        const Usuario = req.body.Usuario
        const Pass = req.body.Pass

        if(!Usuario || !Pass ){
            res.render('login',{
                type: 'warning',
                alert:true,
                alertTitle: "Advertencia",
                alertMessage: "Ingrese un usuario y password",
                alertIcon:'Info',
                showConfirmButton: true,
                timer: false,
                ruta: 'login'
            })
        }else{
            conexion.query('SELECT * FROM users WHERE Usuario = ?', [Usuario], async (error, results)=>{
                if( results.length == 0 || ! (await bcryptjs.compare(Pass, results[0].Pass)) ){
                    res.render('login',{
                        type: 'error',
                        alert:true,
                        alertTitle: "Error",
                        alertMessage: "usuario y/o password incorrectas",
                        alertIcon:'error',
                        showConfirmButton: true,
                        timer: false,
                        ruta: 'login'
                    })
                }else{
                    // inicio de sesion ok
                    const Id = results[0].Id
                    const token = jwt.sign({Id:Id}, process.env.JWT_SECRETO, {
                        expiresIn: process.env.JWT_TIEMPO_EXPIRA
                    })
                    console.log("TOKEN: "+token+" para el USUARIO : "+Usuario)
                    
                    const cookiesOptions = {
                        expires: new Date(Date.now()+process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
                        httpOnly: true
                    }
                    res.cookie('jwt', token, cookiesOptions)
                    res.render('login', {
                        alert:true,
                        alertTitle: "Conexion exitosa",
                        alertMessage: "Login correcto",
                        alertIcon:'success',
                        showConfirmButton: false,
                        time: 800,
                        ruta: ''
                    })
                }
        })
    }
    } catch (error) {
        console.log(error)
    }
}   
//verificar usuario autenticado
exports.isAuthenticated = async (req, res, next)=>{
    if (req.cookies.jwt) {
        try {
            const decodificada = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRETO)
            conexion.query('SELECT * FROM users WHERE id = ?', [decodificada.id], (error, results)=>{
                if(!results){return next()}
                req.user = results[0]
                return next()                    
            })
        } catch (error) {
            console.log(error)
            return next()
        }
    }else{
        res.redirect('/login')
    }
}

exports.logout = (req, res)=>{
    res.clearCookie('jwt')
    return res.redirect('/')
}