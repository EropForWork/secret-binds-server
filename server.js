const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const allowedOrigins = ["http://localhost:5173", process.env.FRONTEND_URL];
// Поддержка JSON и CORS
app.use(express.json());
app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
);

// Подключение к MongoDB Atlas
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Подключено к MongoDB Atlas"))
  .catch((err) => console.error("❌ Ошибка подключения к MongoDB:", err));

// Модель заметки
const cardSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  color: {
    type: String,
    required: true,
  },
  balance: {
    type: Number,
    required: true,
    default: 0,
  },
  lastOperation: {
    amount: Number,
    date: String,
    description: String,
  },
  operations: [
    {
      amount: Number,
      date: String,
      description: String,
    },
  ],
});

const Card = mongoose.model("Card", cardSchema);
// Модель пользователя (только один!)
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", UserSchema);

// 🔐 АВТОРИЗАЦИЯ

// Регистрация — только один раз!
// app.post("/api/auth/register", async (req, res) => {
//   const { username, password } = req.body;

//   if (!username || !password) {
//     return res.status(400).json({ message: "Логин и пароль обязательны" });
//   }

//   const existingUser = await User.findOne({ username });
//   if (existingUser) {
//     return res.status(400).json({ message: "Пользователь уже существует" });
//   }

//   const hashedPassword = await bcrypt.hash(password, 10);
//   const user = new User({ username, password: hashedPassword });
//   await user.save();

//   res.status(201).json({ message: "Регистрация успешна! Теперь войди." });
// });

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

// GET /api/cards — получить все заметки
app.get("/api/cards", authenticateToken, async (req, res) => {
  try {
    const cards = await Card.find().sort({ createdAt: -1 });
    res.json(cards);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/cards — создать заметку
app.post("/api/cards", authenticateToken, async (req, res) => {
  const { name, color, balance = 0 } = req.body;

  if (!name || name.trim() === "") {
    return res.status(400).json({ message: "Название карточки обязательно" });
  }
  if (!color || color.trim() === "") {
    return res.status(400).json({ message: "Цвет карточки обязателен" });
  }

  try {
    const newCard = new Card({
      name: name.trim(),
      color: color.trim(),
      balance: parseFloat(balance),
      lastOperation: {
        amount: parseFloat(balance.toFixed(2)),
        date: new Date().toISOString(),
        description: `Добавление счёта ${name.trim()}`,
      },
    });

    const savedCard = await newCard.save();
    res.status(201).json(savedCard);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.put("/api/cards/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, color, balance, operations, lastOperation } = req.body;

  // Валидация обязательных полей
  if (name !== undefined && (!name || name.trim() === "")) {
    return res.status(400).json({ message: "Название обязательно" });
  }
  if (color !== undefined && (!color || color.trim() === "")) {
    return res.status(400).json({ message: "Цвет обязателен" });
  }
  if (balance !== undefined && typeof balance !== "number") {
    return res.status(400).json({ message: "Баланс должен быть числом" });
  }

  // Разрешаем обновлять любые поля — даже null/undefined
  const updateFields = {};
  if (name !== undefined) updateFields.name = name.trim();
  if (color !== undefined) updateFields.color = color.trim();
  if (balance !== undefined) updateFields.balance = balance;
  if (operations !== undefined) updateFields.operations = operations;
  if (lastOperation !== undefined) updateFields.lastOperation = lastOperation;

  try {
    const card = await Card.findByIdAndUpdate(id, updateFields, {
      new: true,
      runValidators: true,
    });

    if (!card) {
      return res.status(404).json({ message: "Карточка не найдена" });
    }

    res.json(card);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// DELETE /api/cards/:id — удалить заметку
app.delete("/api/cards/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await Card.findByIdAndDelete(id);
    if (!result) {
      return res.status(404).json({ message: "Карточка не найдена" });
    }
    res.json({ message: "Карточка удалена" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// === НОВЫЙ ЭНДПОИНТ: ДОБАВИТЬ ТРАНЗАКЦИЮ === //
app.post("/api/cards/:id/transactions", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { amount, description } = req.body;

  // Валидация
  if (typeof amount !== "number") {
    return res.status(400).json({ message: "Сумма должна быть числом" });
  }
  if (!description || description.trim() === "") {
    return res.status(400).json({ message: "Описание обязательно" });
  }

  try {
    // Найти карточку
    const card = await Card.findById(id);
    if (!card) {
      return res.status(404).json({ message: "Карточка не найдена" });
    }

    // Создать новую операцию
    const newOperation = {
      amount,
      description: description.trim(),
      date: new Date().toISOString(), // ISO формат даты
    };

    // Добавить в историю
    card.operations.push(newOperation);

    // Обновить баланс
    card.balance += amount;

    // Обновить последнюю операцию
    card.lastOperation = newOperation;

    // Сохранить
    await card.save();

    // Ответ — обновлённая карточка
    res.status(201).json(card);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Проверка работоспособности
app.get("/", (req, res) => {
  res.send(
    "Сервер запущен! Подключись через https://polite-banoffee-4ee6f8.netlify.app/."
  );
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на http://localhost:${PORT}`);
});
