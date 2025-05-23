const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

router.post('/register', async (req, res) => {
  const { email, senha } = req.body;
  const userExists = await User.findOne({ email });
  if (userExists) return res.status(400).json({ mensagem: 'Usuário já existe' });

  const senhaHash = await bcrypt.hash(senha, 10);
  const novoUsuario = new User({ email, senha: senhaHash });
  await novoUsuario.save();

  res.status(201).json({ mensagem: 'Usuário criado com sucesso' });
});

router.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  const usuario = await User.findOne({ email });
  if (!usuario) return res.status(400).json({ mensagem: 'Credenciais inválidas' });

  const senhaCorreta = await bcrypt.compare(senha, usuario.senha);
  if (!senhaCorreta) return res.status(400).json({ mensagem: 'Credenciais inválidas' });

  const token = jwt.sign({ id: usuario._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

router.get('/me', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ mensagem: 'Token não fornecido' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const usuario = await User.findById(decoded.id).select('-senha');
    res.json(usuario);
  } catch (err) {
    res.status(401).json({ mensagem: 'Token inválido' });
  }
});

module.exports = router;