const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;

// Configuração do MySQL
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'api',
});

connection.connect();

app.use(bodyParser.json());

// Implemente as rotas aqui

app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedpassword = await bcrypt.hash(password, 10);
    connection.query(
        'INSERT INTO user (name, email, password) VALUES (?, ?, ?)',
        [name, email, hashedpassword],
        (error, results) => {
            if (error) {
                console.error(error);
                res.status(500).send('Erro interno no servidor');
            } else {
                res.status(201).send('Usuário registrado com sucesso');
            }
        }
    );
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    connection.query(
        'SELECT * FROM user WHERE email = ?',
        [email],
        async (error, results) => {
            if (error) {
                console.error(error);
                res.status(500).send('Erro interno no servidor');
            } else if (results.length > 0) {
                const usuario = results[0];

                const passwordCorreta = await bcrypt.compare(password, usuario.password);

                if (passwordCorreta) {
                    const token = jwt.sign({ id: usuario.id, email: usuario.email }, 'seu_segredo', {
                        expiresIn: '1h',
                    });

                    res.json({ token });
                } else {
                    res.status(401).send('Credenciais inválidas');
                }
            } else {
                res.status(401).send('Credenciais inválidas');
            }
        }
    );
});

function verificarToken(req, res, next) {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).send('Token não fornecido');
    }
    jwt.verify(token, 'seu_segredo', (error, decoded) => {
        if (error) {
            return res.status(403).send('Token inválido');
        }

        req.usuario = decoded;
        next();
    });
}

// Rotas Protegidas

app.patch('/users/:id', verificarToken, async (req, res) => {
    const userId = req.params.id;
    const { name, email, password } = req.body;
    if (!name && !email && !password) {
        return res.status(400).send('Nenhum campo fornecido para atualização');
    }

    const updateFields = [];
    const updateValues = [];

    if (name) {
        updateFields.push('name = ?');
        updateValues.push(name);
    }

    if (email) {
        updateFields.push('email = ?');
        updateValues.push(email);
    }

    if (password) {
        const hashedpassword = await bcrypt.hash(password, 10);
        updateFields.push('password = ?');
        updateValues.push(hashedpassword);
    }

    connection.query(
        `UPDATE user SET ${updateFields.join(', ')} WHERE id = ?`,
        [...updateValues, userId],
        (error, results) => {
            if (error) {
                console.error(error);
                res.status(500).send('Erro interno no servidor');
            } else if (results.affectedRows > 0) {
                res.send('Usuário atualizado com sucesso');
            } else {
                res.status(404).send('Usuário não encontrado');
            }
        }
    );
});

app.delete('/users/:id', verificarToken, (req, res) => {
    const userId = req.params.id;
    connection.query('DELETE FROM user WHERE id = ?', [userId], (error, results) => {
        if (error) {
            console.error(error);
            res.status(500).send('Erro interno no servidor');
        } else if (results.affectedRows > 0) {
            res.send('Usuário deletado com sucesso');
        } else {
            res.status(404).send('Usuário não encontrado');
        }
    });
});

app.get('/salary', verificarToken, (req, res) => {
    const { pagina, tamanhoPagina } = req.query;
    const paginaAtual = parseInt(pagina, 10) || 1;
    const limite = parseInt(tamanhoPagina, 10) || 10;
    const offset = (paginaAtual - 1) * limite;
    connection.query(
        'SELECT * FROM salary LIMIT ? OFFSET ?',
        [limite, offset],
        (error, results) => {
            if (error) {
                console.error(error);
                res.status(500).send('Erro interno no servidor');
            } else {
                res.json(results);
            }
        }
    );
});

app.get('/salary/:id', verificarToken, (req, res) => {
    const salaryId = req.params.id;
    connection.query('SELECT * FROM salary WHERE id = ?', [salaryId], (error, results) => {
        if (error) {
            console.error(error);
            res.status(500).send('Erro interno no servidor');
        } else if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).send('Informação não encontrada');
        }
    });
});

app.post('/salary', verificarToken, (req, res) => {
    const { age, gender, education, title, experience, salary, country, race } = req.body;
  
    connection.query(
      'INSERT INTO salary (AGE, GENDER, EDUCATION, TITLE, EXPERIENCE, SALARY, COUNTRY, RACE) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [age, gender, education, title, experience, salary, country, race],
      (error, results) => {
        if (error) {
          console.error(error);
          res.status(500).send('Erro interno no servidor');
        } else {
          res.status(201).send('Entrada realizada com sucesso');
        }
      }
    );
  });

  app.patch('/salary/:id', verificarToken, async (req, res) => {
    const userId = req.params.id;
    const { age, gender, education, title, experience, salary, country, race } = req.body;
  
    // Verifique se algum campo foi fornecido para atualização
    if (!age && !gender && !education && !title && !experience && !salary && !country && !race) {
      return res.status(400).send('Nenhum campo fornecido para atualização');
    }
  
    // Construa a parte da consulta SQL dinamicamente com base nos campos fornecidos
    const updateFields = [];
    const updateValues = [];
  
    if (age) {
      updateFields.push('age = ?');
      updateValues.push(age);
    }
  
    if (gender) {
      updateFields.push('gender = ?');
      updateValues.push(gender);
    }
  
    if (education) {
      updateFields.push('education = ?');
      updateValues.push(education);
    }
  
    if (title) {
      updateFields.push('title = ?');
      updateValues.push(title);
    }
  
    if (experience) {
      updateFields.push('experience = ?');
      updateValues.push(experience);
    }
  
    if (salary) {
      updateFields.push('salary = ?');
      updateValues.push(salary);
    }
  
    if (country) {
      updateFields.push('country = ?');
      updateValues.push(country);
    }
  
    if (race) {
      updateFields.push('race = ?');
      updateValues.push(race);
    }
  
    connection.query(
      `UPDATE salary SET ${updateFields.join(', ')} WHERE id = ?`,
      [...updateValues, userId],
      (error, results) => {
        if (error) {
          console.error(error);
          res.status(500).send('Erro interno no servidor');
        } else if (results.affectedRows > 0) {
          res.send('Informação Alterada com sucesso');
        } else {
          res.status(404).send('Informação não encontrada');
        }
      }
    );
  });

  app.delete('/salary/:id', verificarToken, (req, res) => {
    const salaryId = req.params.id;
  
    connection.query('DELETE FROM salary WHERE id = ?', [salaryId], (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).send('Erro interno no servidor');
      } else if (results.affectedRows > 0) {
        res.send('Informação deletada com sucesso');
      } else {
        res.status(404).send('Informação não encontrada');
      }
    });
  });