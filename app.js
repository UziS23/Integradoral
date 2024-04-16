// app.js

const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const jwt = require('jsonwebtoken'); // Importamos jsonwebtoken
const session = require('express-session'); // Importamos express-session
const CryptoJS = require('crypto-js'); // Importamos CryptoJS
const app = express();

const connection = mysql.createConnection({
    host: 'sql5.freesqldatabase.com',
    user: 'sql5699030',
    password: 'qllXpPEnH3',
    database: 'sql5699030'
});

connection.connect();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'l?k1@+y2`#3T*8d$!9m0P&/4a5N%6sU7qC*w8E(z9R0)-A', resave: false, saveUninitialized: true })); // Configuración de express-session

const secretKey = 'l?k1@+y2`#3T*8d$!9m0P&/4a5N%6sU7qC*w8E(z9R0)-A'; // Cambia esto por tu propia clave secreta

app.get('/', (req, res) => {
    const captcha = generarCaptcha(); // Generar captcha aleatorio
    req.session.captcha = captcha; // Almacenar captcha en la sesión
    res.render('index', { captcha });
});

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

    app.get('/diseno', (req, res) => {
        res.render('diseno');
    });
    
    app.get('/nosotros', (req, res) => {
        res.render('nosotros');
    });

    app.get('/miperfil', (req, res) => {
        res.render('miperfil');
    });

    app.get('/disenoen', (req, res) => {
        res.render('disenoen');
    });

    app.get('/nosotrosen', (req, res) => {
        res.render('nosotrosen');
    });

    app.get('/miperfilen', (req, res) => {
        res.render('miperfilen');
    });
    
    app.get('/protegido', verificarToken, (req, res) => {
        res.send('¡Acceso permitido!'); // Si el token es válido, permitimos el acceso
    });

    const query = `SELECT * FROM usuarios WHERE usuario = ? AND contrasena = ?`;

    connection.query(query, [usuario, decryptedPasswordStr], (error, results, fields) => {
        if (error) throw error;

        if (results.length > 0) {
            const token = jwt.sign({ usuario }, secretKey, { expiresIn: '1h' }); // Token expira en 1 hora
            res.setHeader('Authorization', token); // Enviamos el token en el encabezado Authorization
            req.session.userId = results[0].ID;
            console.log("ID del usuario almacenado en la sesión:", req.session.userId);

            const updateQuery = `UPDATE usuarios SET IdS = ? WHERE usuario = ?`;
            connection.query(updateQuery, ['si', usuario], (updateError, updateResults, updateFields) => {
                if (updateError) throw updateError;
                console.log('Campo IdS actualizado correctamente.');
                
                res.redirect('/diseno');
            });
        } else {
            res.status(401).send('Usuario o contraseña incorrectos'); // Devolvemos error 401 si las credenciales son incorrectas
        }
    });
});

app.get('/miperfil', (req, res) => {
    // Verificar si el usuario está autenticado
    if (!req.session.userId) {
        res.status(401).send('Acceso no autorizado'); // Si no hay un ID de usuario en la sesión, enviar error 401
        return;
    }

    // Consultar datos del usuario utilizando el ID almacenado en la sesión
    const query = `SELECT * FROM usuarios WHERE ID = ?`;
    connection.query(query, [req.session.userId], (error, results, fields) => {
        if (error) throw error;

        if (results.length > 0) {
            const userData = results[0]; // Suponiendo que solo hay un registro de usuario con ese ID
            console.log('Datos del usuario:', userData); // Agrega este registro de consola para depurar
            // Renderizar la página 'miperfil' con los datos del usuario
            res.render('miperfil', { usuario: userData });
        } else {
            res.status(404).send('Usuario no encontrado');
        }
    });
});

app.get('/miperfilen', (req, res) => {
    // Verificar si el usuario está autenticado
    if (!req.session.userId) {
        res.status(401).send('Acceso no autorizado'); // Si no hay un ID de usuario en la sesión, enviar error 401
        return;
    }

    // Consultar datos del usuario utilizando el ID almacenado en la sesión
    const query = `SELECT * FROM usuarios WHERE ID = ?`;
    connection.query(query, [req.session.userId], (error, results, fields) => {
        if (error) throw error;

        if (results.length > 0) {
            const userData = results[0]; // Suponiendo que solo hay un registro de usuario con ese ID
            console.log('Datos del usuario:', userData); // Agrega este registro de consola para depurar
            // Renderizar la página 'miperfil' con los datos del usuario
            res.render('miperfilen', { usuario: userData });
        } else {
            res.status(404).send('Usuario no encontrado');
        }
    });
});


app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            res.status(500).send('Error al cerrar sesión');
        } else {
            eliminarRutas();
            res.redirect('/');

        }
    });
});

app.post('/updatePassword', (req, res) => {
    const { nuevacontra } = req.body; // Obtén la nueva contraseña del cuerpo de la solicitud

    // Realiza la actualización de la contraseña en la base de datos
    const updateQuery = `UPDATE usuarios SET contrasena = ? WHERE ID = ?`;
    connection.query(updateQuery, [nuevacontra, req.session.userId], (error, results, fields) => {
        if (error) {
            console.error('Error al actualizar la contraseña:', error);
            res.status(500).send('Error al actualizar la contraseña');
        } else {
            console.log('Contraseña actualizada correctamente.');
            res.redirect('/miperfil'); // Redirige al usuario a la página de su perfil después de actualizar la contraseña
        }
    });
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

const path = require('path'); // Importa el módulo 'path'

app.use('/assets', express.static(path.join(__dirname, 'views', 'assets')));

function generarCaptcha() {
    const caracteres = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890';
    let captcha = '';
    for (let i = 0; i < 5; i++) {
        captcha += caracteres.charAt(Math.floor(Math.random() * caracteres.length));
    }
    return captcha;
}
function eliminarRutas() {
    // Eliminar definiciones de ruta después de cerrar sesión
    app._router.stack = app._router.stack.filter((layer) => {
        return !['/diseno', '/nosotros', '/protegido'].includes(layer.route?.path);
    });
}

app.listen(3000, () => {
    console.log('Servidor iniciado en http://localhost:3000');
});
