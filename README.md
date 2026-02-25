
---

# 📝 🔟 bin_chek-staus-sign_sbp-Telegam_bot

# bin_chek-staus-sign_sbp-Telegam_bot

![Главный скриншот](screenshots/screen1.jpg)

## О проекте
Telegram-бот для проверки платежей через СБП и уведомления о статусе.

## 🚀 Возможности
- Проверка статуса платежей через API Газпромбанка (PGA)
- Валидация банковских карт (BIN Check) через APILayer
- Генерация RSA-ключей и проверка цифровых подписей СБП
- Формирование строк для подписи (порядок следования / алфавитный)
- Экранирование HTML и логирование действий

## 🛠 Технологии
- Python 3.10, asyncio
- Telegram Bot API
- cryptography (RSA, SHA256)
- requests (HTTP-запросы к API)
- Интеграция с API Газпромбанка и APILayer

## Скриншоты
![Скриншот 1](screenshots/screen2.jpg)

## Установка и запуск

git clone https://github.com/IOXNSUN/bin_chek-staus-sign_sbp-Telegam_bot.git
cd bin_chek-staus-sign_sbp-Telegam_bot
python bot.py

Ссылки
- 🚀 [Telegram-бот](https://t.me/status_request_bot)
