const express = require('express');
const path = require('path');
const app = express();
const port = 3000;
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');

// Clave secreta para firmar el token
const secretKey = 'tu_clave_secreta';

// Middleware para manejar JSON
app.use(express.json());

// Crear la conexión a la base de datos
const connection = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'loginapi',
});

connection.getConnection((err, conn) => {
  if (err) {
    console.error("Error al conectar con la base de datos:", err.message);
  } else {
    console.log("Conexión a la base de datos exitosa");
    conn.release();
  }
});

// Middleware de verificación de token para rutas protegidas
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(403).send('Token requerido');

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(401).send('Token inválido');
    req.usuario = decoded.usuario;
    next();
  });
};

// Ruta POST para login y generación de token
app.post('/login', async (req, res) => {
  const { usuario, clave } = req.body;
  try {
    const [results] = await connection.query(
      "SELECT * FROM `usuarios` WHERE `usuario` = ? AND `clave` = ?",
      [usuario, clave]
    );

    if (results.length > 0) {
      const token = jwt.sign({ usuario: results[0].usuario }, secretKey, { expiresIn: '1h' });
      res.status(200).json({ message: 'Inicio de sesión correcto', token });
    } else {
      res.status(401).send('Datos incorrectos');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error en el servidor');
  }
});

// Ruta protegida GET para obtener todos los usuarios, solo accesible con token
app.get('/usuarios', verifyToken, async (req, res) => {
  try {
    const [results] = await connection.query('SELECT * FROM `usuarios`');
    res.status(200).json(results);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al obtener los usuarios');
  }
});

// Ruta para verificar si el token sigue siendo válido
app.get('/verifyToken', verifyToken, (req, res) => {
  res.status(200).json({ message: 'Token válido', usuario: req.usuario });
});

// Rutas para registro, actualización y eliminación de usuarios (requieren token)
app.post('/register', async (req, res) => { /* Código de registro */ });
app.put('/update', verifyToken, async (req, res) => { /* Código de actualización */ });
app.patch('/updatePassword', verifyToken, async (req, res) => { /* Código de actualización de clave */ });
app.delete('/delete', verifyToken, async (req, res) => { /* Código de eliminación */ });

// Middleware para servir archivos estáticos de React en producción
if (process.env.NODE_ENV === 'production') {
  // Asegúrate de que 'build' esté en la raíz del proyecto
  app.use(express.static(path.join(__dirname, '../build')));

  // Ruta para manejar cualquier solicitud que no coincida con una ruta de la API
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../build', 'index.html'));
  });
}

// Servidor en escucha
app.listen(port, () => {
  console.log(`API escuchando en http://localhost:${port}`);
});
