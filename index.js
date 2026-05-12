require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const app = express();

const PORT = process.env.PORT || 3000;

const saltRounds = 12;

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

const mongoUri =
    `mongodb+srv://${process.env.MONGODB_USER}:` +
    `${process.env.MONGODB_PASSWORD}@` +
    `${process.env.MONGODB_HOST}/` +
    `${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;

let userCollection;

async function startServer() {

    const client = new MongoClient(mongoUri);

    await client.connect();

    const db = client.db(process.env.MONGODB_DATABASE);

    userCollection = db.collection('users');

    app.use(
        session({
            secret: process.env.NODE_SESSION_SECRET,

            store: MongoStore.create({
                mongoUrl: mongoUri,
                collectionName: 'sessions'
            }),

            saveUninitialized: false,
            resave: true,

            cookie: {
                maxAge: 1000 * 60 * 60
            }
        })
    );

    function isValidSession(req, res, next) {

        if (req.session.authenticated) {
            next();
        }
        else {
            res.redirect('/login');
        }
    }

    function isAdmin(req, res, next) {

        if (req.session.user_type === 'admin') {
            next();
        }
        else {

            res.status(403);

            res.render('error', {
                message: 'You are not authorized to view this page.'
            });
        }
    }

    app.get('/', (req, res) => {

        res.render('index', {
            authenticated: req.session.authenticated,
            name: req.session.name
        });
    });

    app.get('/signup', (req, res) => {

        res.render('signup');
    });

    app.post('/signupSubmit', async (req, res) => {

        const schema = Joi.object({
            name: Joi.string().max(50).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(50).required()
        });

        const validationResult = schema.validate(req.body);

        if (validationResult.error) {

            return res.render('error', {
                message: validationResult.error.details[0].message
            });
        }

        const { name, email, password } = req.body;

        const existingUser = await userCollection.findOne({
            email: email
        });

        if (existingUser) {

            return res.render('error', {
                message: 'User already exists.'
            });
        }

        const hashedPassword = await bcrypt.hash(
            password,
            saltRounds
        );

        let userType = 'user';

        if (email === 'admin@email.com') {
            userType = 'admin';
        }

        await userCollection.insertOne({
            name,
            email,
            password: hashedPassword,
            user_type: userType
        });

        req.session.authenticated = true;
        req.session.name = name;
        req.session.email = email;
        req.session.user_type = userType;

        res.redirect('/members');
    });

    app.get('/login', (req, res) => {

        res.render('login');
    });

    app.post('/loginSubmit', async (req, res) => {

        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().max(50).required()
        });

        const validationResult = schema.validate(req.body);

        if (validationResult.error) {

            return res.render('error', {
                message: 'Invalid email/password.'
            });
        }

        const { email, password } = req.body;

        const user = await userCollection.findOne({
            email: email
        });

        if (!user) {

            return res.render('error', {
                message: 'User and password not found.'
            });
        }

        const validPassword = await bcrypt.compare(
            password,
            user.password
        );

        if (!validPassword) {

            return res.render('error', {
                message: 'User and password not found.'
            });
        }

        req.session.authenticated = true;
        req.session.name = user.name;
        req.session.email = user.email;
        req.session.user_type = user.user_type;

        res.redirect('/members');
    });

    app.get('/members', isValidSession, (req, res) => {

        const images = [
            'fish1.jpg',
            'fish2.jpg',
            'fish3.png'
        ];

        res.render('members', {
            name: req.session.name,
            images
        });
    });

    app.get(
        '/admin',
        isValidSession,
        isAdmin,
        async (req, res) => {

            const users = await userCollection
                .find({})
                .toArray();

            res.render('admin', {
                users
            });
        }
    );

    app.get(
        '/promote/:email',
        isValidSession,
        isAdmin,
        async (req, res) => {

            const schema = Joi.object({
                email: Joi.string().email().required()
            });

            const validationResult =
                schema.validate(req.params);

            if (validationResult.error) {

                return res.render('error', {
                    message: 'Invalid email.'
                });
            }

            await userCollection.updateOne(
                {
                    email: req.params.email
                },
                {
                    $set: {
                        user_type: 'admin'
                    }
                }
            );

            res.redirect('/admin');
        }
    );

    app.get(
        '/demote/:email',
        isValidSession,
        isAdmin,
        async (req, res) => {

            const schema = Joi.object({
                email: Joi.string().email().required()
            });

            const validationResult =
                schema.validate(req.params);

            if (validationResult.error) {

                return res.render('error', {
                    message: 'Invalid email.'
                });
            }

            await userCollection.updateOne(
                {
                    email: req.params.email
                },
                {
                    $set: {
                        user_type: 'user'
                    }
                }
            );

            res.redirect('/admin');
        }
    );

    app.get('/logout', (req, res) => {

        req.session.destroy(() => {

            res.redirect('/');
        });
    });

    app.use((req, res) => {

        res.status(404);

        res.render('404');
    });

    app.listen(PORT, () => {

        console.log(`Server running on port ${PORT}`);
    });
}

startServer();