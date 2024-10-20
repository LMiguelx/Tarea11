const express = require('express');
const mongoose = require('mongoose');
const Joi = require('joi'); 
const bcrypt = require('bcrypt'); 

const router = express.Router();

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});

const User = mongoose.model('User', userSchema);

const userValidationSchema = Joi.object({
  name: Joi.string().min(3).required().messages({
    'string.empty': 'El nombre es obligatorio',
    'string.min': 'El nombre debe tener al menos 3 caracteres'
  }),
  email: Joi.string().email().required().messages({
    'string.empty': 'El correo electrónico es obligatorio',
    'string.email': 'Debe proporcionar un correo electrónico válido'
  }),
  password: Joi.string()
    .pattern(new RegExp('^(?=.*[A-Z])(?=.*[0-9])(?=.*[a-zA-Z]).{8,}$'))
    .required()
    .messages({
      'string.empty': 'La contraseña es obligatoria',
      'string.pattern.base': 'La contraseña debe tener al menos 8 caracteres, una letra mayúscula y un número'
    })
});

router.get('/', async (req, res) => {
  const users = await User.find();
  res.render('index', { users });
});

router.post('/', async (req, res) => {
  const { error } = userValidationSchema.validate(req.body, { abortEarly: false });

  if (error) {
    const errors = error.details.map(err => err.message);
    return res.status(400).render('index', { users: await User.find(), errors });
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  const newUser = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword 
  });
  
  await newUser.save();
  res.redirect('/users');
});

router.post('/update/:id', async (req, res) => {
  const { error } = userValidationSchema.validate(req.body, { abortEarly: false });

  if (error) {
    const errors = error.details.map(err => err.message);
    const user = await User.findById(req.params.id);
    return res.status(400).render('partials/edit', { user, errors });
  }

  const updateData = { ...req.body };

  if (req.body.password) {
    const salt = await bcrypt.genSalt(10);
    updateData.password = await bcrypt.hash(req.body.password, salt);
  } else {
    delete updateData.password;
  }

  await User.findByIdAndUpdate(req.params.id, updateData);
  res.redirect('/users');
});

router.get('/edit/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.render('partials/edit', { user });
});

router.get('/delete/:id', async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.redirect('/users');
});

router.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(400).send('Usuario no encontrado');
  }

  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword) {
    return res.status(400).send('Contraseña incorrecta');
  }

  res.send('Inicio de sesión exitoso');
});

module.exports = router;
