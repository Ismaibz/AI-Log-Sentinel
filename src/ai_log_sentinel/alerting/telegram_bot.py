from __future__ import annotations

import logging

from ai_log_sentinel.alerting.dispatcher import AlertDispatcher
from ai_log_sentinel.alerting.formatters import format_telegram
from ai_log_sentinel.mitigation.hitl import HITLGate
from ai_log_sentinel.models.alert import Alert

try:
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.ext import Application, CallbackQueryHandler, ContextTypes

    _TELEGRAM_AVAILABLE = True
except ImportError:
    _TELEGRAM_AVAILABLE = False

logger = logging.getLogger(__name__)


class TelegramDispatcher(AlertDispatcher):
    def __init__(self, bot_token: str, chat_id: str, hitl: HITLGate | None = None) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.hitl = hitl
        self._application: Application | None = None

    async def send(self, alert: Alert) -> bool:
        if not _TELEGRAM_AVAILABLE:
            logger.warning("python-telegram-bot not installed; cannot send alert")
            return False
        if not self.bot_token or not self.chat_id:
            logger.warning("Telegram bot_token or chat_id is empty")
            return False

        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        "\u2705 Approve",
                        callback_data=f"approve:{alert.id}",
                    ),
                    InlineKeyboardButton(
                        "\u274c Reject",
                        callback_data=f"reject:{alert.id}",
                    ),
                ]
            ]
        )

        try:
            from telegram import Bot

            bot = Bot(token=self.bot_token)
            await bot.send_message(
                chat_id=self.chat_id,
                text=format_telegram(alert),
                parse_mode="MarkdownV2",
                reply_markup=keyboard,
            )
            return True
        except Exception:
            logger.exception("Failed to send Telegram alert %s", alert.id)
            return False

    async def handle_response(self, alert_id: str, approved: bool) -> None:
        if self.hitl is None:
            return
        if approved:
            await self.hitl.approve(alert_id)
        else:
            await self.hitl.reject(alert_id)

    async def _callback_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        action, alert_id = query.data.split(":", 1)
        approved = action == "approve"
        if self.hitl:
            if approved:
                await self.hitl.approve(alert_id)
            else:
                await self.hitl.reject(alert_id)
        await query.edit_message_reply_markup(reply_markup=None)

    async def start_polling(self) -> None:
        if not _TELEGRAM_AVAILABLE:
            logger.warning("python-telegram-bot not installed; cannot start polling")
            return
        self._application = Application.builder().token(self.bot_token).build()
        self._application.add_handler(CallbackQueryHandler(self._callback_handler))
        await self._application.initialize()
        await self._application.start()
        await self._application.updater.start_polling()
        logger.info("Telegram bot polling started")

    async def stop_polling(self) -> None:
        if self._application is not None:
            await self._stop_application()

    async def _stop_application(self) -> None:
        if self._application is None:
            return
        try:
            await self._application.updater.stop()
            await self._application.stop()
            await self._application.shutdown()
        except Exception:
            logger.exception("Error stopping Telegram bot")
        self._application = None
