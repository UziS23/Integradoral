// app.js

const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const jwt = require('jsonwebtoken'); // Importamos jsonwebtoken
const session = require('express-session'); // Importamos express-session
const CryptoJS = require('crypto-js'); // Importamos CryptoJS
const app = express();

// Configuración de MySQL
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'guardiantrack'
});

connection.connect();

// Configuración de Express
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'l?k1@+y2`#3T*8d$!9m0P&/4a5N%6sU7qC*w8E(z9R0)-A', resave: false, saveUninitialized: true })); // Configuración de express-session

// Secret key para firmar el token JWT
const secretKey = 'l?k1@+y2`#3T*8d$!9m0P&/4a5N%6sU7qC*w8E(z9R0)-A'; // Cambia esto por tu propia clave secreta

// Ruta para mostrar el formulario de login
app.get('/', (req, res) => {
    const captcha = generarCaptcha(); // Generar captcha aleatorio
    req.session.captcha = captcha; // Almacenar captcha en la sesión
    res.render('index', { captcha });
});

// Ruta para procesar el formulario de login y generar token
app.post('/login', (req, res) => {
    const { usuario, contraseña, captcha } = req.body;
    const captchaGuardado = req.session.captcha; // Obtener captcha almacenado en la sesión

    if (captcha !== captchaGuardado) {
        res.status(401).send('Captcha incorrecto'); // Devolvemos error 401 si el captcha es incorrecto
        return;
    }

    // Desencriptar la contraseña
    const key = CryptoJS.enc.Utf8.parse('8080808080808080');
    const iv = CryptoJS.enc.Utf8.parse('8080808080808080');
    const decryptedPassword = CryptoJS.AES.decrypt(contraseña, key, {
        keySize: 128 / 8,
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    const decryptedPasswordStr = decryptedPassword.toString(CryptoJS.enc.Utf8);

    const query = `SELECT * FROM usuarios WHERE usuario = ? AND contrasena = ?`;

    connection.query(query, [usuario, decryptedPasswordStr], (error, results, fields) => {
        if (error) throw error;

        if (results.length > 0) {
            // Si el usuario existe, generamos el token JWT
            const token = jwt.sign({ usuario }, secretKey, { expiresIn: '1h' }); // Token expira en 1 hora
            res.setHeader('Authorization', token); // Enviamos el token en el encabezado Authorization
            
            // Aquí realizamos la actualización del campo IdS
            const updateQuery = `UPDATE usuarios SET IdS = ? WHERE usuario = ?`;
            connection.query(updateQuery, ['si', usuario], (updateError, updateResults, updateFields) => {
                if (updateError) throw updateError;
                console.log('Campo IdS actualizado correctamente.');
                setTimeout(() => {
                    res.redirect('views/diseno.ejs');
                }, 2000);
            });
        } else {
            res.status(401).send('Usuario o contraseña incorrectos'); // Devolvemos error 401 si las credenciales son incorrectas
        }
    });
});

// Ruta protegida que requiere token para acceder
app.get('/protegido', verificarToken, (req, res) => {
    res.send('¡Acceso permitido!'); // Si el token es válido, permitimos el acceso
});

// Función middleware para verificar el token
function verificarToken(req, res, next) {
    const token = req.headers['authorization'];

    if (typeof token !== 'undefined') {
        jwt.verify(token, secretKey, (err, authData) => {
            if (err) {
                res.sendStatus(403); // Si el token no es válido, devolvemos error 403
            } else {
                req.authData = authData; // Si el token es válido, almacenamos los datos de autenticación en el objeto de solicitud
                next(); // Pasamos al siguiente middleware o ruta
            }
        });
    } else {
        res.sendStatus(403); // Si no se proporciona el token, devolvemos error 403
    }
}

// Función para generar un captcha aleatorio de 5 letras
function generarCaptcha() {
    const caracteres = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890';
    let captcha = '';
    for (let i = 0; i < 5; i++) {
        captcha += caracteres.charAt(Math.floor(Math.random() * caracteres.length));
    }
    return captcha;
}

app.listen(3000, () => {
    console.log('Servidor iniciado en http://localhost:3000');
});
