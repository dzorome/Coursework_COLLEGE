// Импорт модулей
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const db = new sqlite3.Database('./db/employees.db');

app.use(express.static('public'));
app.set('views', './views');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true
}));
app.set('view engine', 'ejs');

// Middleware для проверки аутентификации и роли
function checkAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

function checkAdmin(req, res, next) {
    if (req.session.role === 'staff') {
        next();
    } else {
        res.status(403).send('Доступ запрещен');
    }
}

// Регистрация
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, 'client'], function (err) {
        if (err) {
            return res.status(500).send('Ошибка регистрации');
        }
        res.redirect('/login');
    });
});

// Вход
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) {
            return res.status(401).send('Неправильное имя пользователя или пароль');
        }

        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).send('Неправильное имя пользователя или пароль');
        }

        req.session.userId = user.id;
        req.session.role = user.role;
        res.redirect(user.role === 'staff' ? '/admin' : '/');
    });
});

// Админ-панель
app.get('/admin', checkAuth, checkAdmin, (req, res) => {
    db.all('SELECT * FROM employees', [], (err, employees) => {
        if (err) {
            return res.status(500).send('Ошибка базы данных');
        }
        db.all("SELECT * FROM prescriptions", (err, prescriptions) => {
            if (err) {
                console.error("Error fetching prescriptions:", err);
                return res.status(500).send("Ошибка сервера при получении данных рецептов");
            }
            res.render('admin', { employees: employees, prescriptions: prescriptions });
        });
    });
});

// Маршрут для добавления клиента
app.post('/admin/addClient', checkAuth, checkAdmin, (req, res) => {
    const { name, email } = req.body;
    db.run('INSERT INTO clients (name, email) VALUES (?, ?)', [name, email], function (err) {
        if (err) {
            return res.status(500).send('Ошибка при добавлении клиента');
        }
        res.redirect('/admin');
    });
});

// Маршрут для фильтрации сотрудников
app.get('/admin/filterEmployees', checkAuth, checkAdmin, (req, res) => {
    const { role, name } = req.query;
    let query = 'SELECT * FROM employees WHERE 1=1';
    const params = [];

    if (role) {
        query += ' AND role = ?';
        params.push(role);
    }
    if (name) {
        query += ' AND name LIKE ?';
        params.push(`%${name}%`);
    }

    db.all(query, params, (err, employees) => {
        if (err) return res.status(500).send('Ошибка базы данных');
        db.all("SELECT * FROM prescriptions", [], (err, prescriptions) => {
            if (err) {
                console.error("Ошибка при получении рецептов:", err);
                return res.status(500).send("Ошибка сервера");
            }
            res.render('admin', { employees: employees, prescriptions: prescriptions });
        });
    });
});

// Маршрут для экспорта записей
app.get('/admin/exportRecords', checkAuth, checkAdmin, (req, res) => {
    db.all('SELECT * FROM employees', [], (err, employees) => {
        if (err) return res.status(500).send('Ошибка базы данных');

        const csv = employees.map(emp => `${emp.id},${emp.name},${emp.position}`).join('\n');
        res.header('Content-Type', 'text/csv');
        res.attachment('employees.csv');
        res.send(csv);
    });
});

// Выход
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Запуск сервера
app.listen(3000, () => {
    console.log('Сервер запущен на http://localhost:3000');
});
