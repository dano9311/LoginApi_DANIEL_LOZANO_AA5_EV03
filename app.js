const express = require('express');
const app = express();
const port = 3000;
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken'); // Importamos jsonwebtoken

// Clave secreta para firmar el token
const secretKey = 'tu_clave_secreta'; // Usa una clave segura y mantenla privada

// Middleware para manejar JSON
app.use(express.json());

// Crear la conexión a la base de datos
const connection = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '', // Asegúrate de que coincida con tu configuración
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
    req.usuario = decoded.usuario; // Guardamos el usuario en el request para su uso posterior
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
      // Credenciales válidas, creamos el token
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

// Ruta POST para registrar un nuevo usuario (sin autenticación requerida)
app.post('/register', async (req, res) => {
  const { usuario, clave } = req.body;

  if (!usuario || !clave) {
    return res.status(400).json({ message: 'Usuario y clave son requeridos' });
  }

  try {
    await connection.query('INSERT INTO usuarios (usuario, clave) VALUES (?, ?)', [usuario, clave]);
    res.status(201).json({ message: 'Usuario registrado con éxito' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al registrar usuario' });
  }
});

// Ruta PUT para actualizar un usuario existente (requiere token)
app.put('/update', verifyToken, async (req, res) => {
  const { usuario, nuevoUsuario, nuevaClave } = req.body;
  try {
    const [results] = await connection.query(
      "UPDATE `usuarios` SET `usuario` = ?, `clave` = ? WHERE `usuario` = ?",
      [nuevoUsuario, nuevaClave, usuario]
    );

    if (results.affectedRows > 0) {
      res.status(200).send('Usuario actualizado correctamente');
    } else {
      res.status(404).send('Usuario no encontrado');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al actualizar el usuario');
  }
});

// Ruta PATCH para actualizar parcialmente un usuario (requiere token)
app.patch('/updatePassword', verifyToken, async (req, res) => {
  const { usuario, nuevaClave } = req.body;
  try {
    const [results] = await connection.query(
      "UPDATE `usuarios` SET `clave` = ? WHERE `usuario` = ?",
      [nuevaClave, usuario]
    );

    if (results.affectedRows > 0) {
      res.status(200).send('Clave actualizada correctamente');
    } else {
      res.status(404).send('Usuario no encontrado');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al actualizar la clave');
  }
});

// Ruta DELETE para eliminar un usuario (requiere token)
app.delete('/delete', verifyToken, async (req, res) => {
  const { usuario } = req.body;
  try {
    const [results] = await connection.query(
      "DELETE FROM `usuarios` WHERE `usuario` = ?",
      [usuario]
    );

    if (results.affectedRows > 0) {
      res.status(200).send('Usuario eliminado correctamente');
    } else {
      res.status(404).send('Usuario no encontrado');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al eliminar el usuario');
  }
});

// Servidor en escucha
app.listen(port, () => {
  console.log(`API escuchando en http://localhost:${port}`);
});
