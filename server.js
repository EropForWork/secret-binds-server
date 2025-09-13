const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// Поддержка JSON и CORS
app.use(express.json());
app.use(
  cors({
    origin: ["https://твой-сайт.vercel.app"], // 👈 ТОЛЬКО ТВОЙ САЙТ!
    credentials: true,
  })
);

// Подключение к MongoDB Atlas
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Подключено к MongoDB Atlas"))
  .catch((err) => console.error("❌ Ошибка подключения к MongoDB:", err));

// Модель заметки
const NoteSchema = new mongoose.Schema({
  text: String,
  createdAt: { type: Date, default: Date.now },
});

const Note = mongoose.model("Note", NoteSchema);

// Модель пользователя (только один!)
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", UserSchema);

// 🔐 АВТОРИЗАЦИЯ

// Регистрация — только один раз!
app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Логин и пароль обязательны" });
  }

  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ message: "Пользователь уже существует" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();

  res.status(201).json({ message: "Регистрация успешна! Теперь войди." });
});

// Логин — выдаём токен
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Введите логин и пароль" });
  }

  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ message: "Неверный логин или пароль" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Неверный логин или пароль" });
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
  res.json({ token });
});

// 🔒 ЗАЩИЩЁННЫЕ ЭНДПОИНТЫ — ТОЛЬКО С ТОКЕНОМ!

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// GET /api/notes — получить все заметки
app.get("/api/notes", authenticateToken, async (req, res) => {
  try {
    const notes = await Note.find().sort({ createdAt: -1 });
    res.json(notes);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/notes — создать заметку
app.post("/api/notes", authenticateToken, async (req, res) => {
  const { text } = req.body;
  if (!text || text.trim() === "") {
    return res.status(400).json({ message: "Заметка не может быть пустой" });
  }

  const note = new Note({ text });
  try {
    const savedNote = await note.save();
    res.status(201).json(savedNote);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// DELETE /api/notes/:id — удалить заметку
app.delete("/api/notes/:id", authenticateToken, async (req, res) => {
  try {
    const result = await Note.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ message: "Заметка не найдена" });
    res.json({ message: "Заметка удалена" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Проверка работоспособности
app.get("/", (req, res) => {
  res.send("🔒 Secure Notes API — работает! Подключись через React.");
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на http://localhost:${PORT}`);
});
