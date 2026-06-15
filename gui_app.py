from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, filedialog

import db
import auth
import vault

BG = "#F4F6FA"
SIDEBAR = "#0F172A"
CARD = "#FFFFFF"
TEXT = "#111827"
MUTED = "#6B7280"
ACCENT = "#6366F1"
ACCENT_DARK = "#4F46E5"
DANGER = "#EF4444"
DANGER_BG = "#FEE2E2"
LIGHT_BTN = "#EEF2FF"
BORDER = "#DDE2EA"
FIELD_BG = "#FFFFFF"

FONT = "Arial"


def sys_platform() -> str:
    import sys
    if sys.platform.startswith("darwin"):
        return "mac"
    if sys.platform.startswith("win"):
        return "win"
    return "linux"


def open_with_default_app(file_path: str) -> None:
    try:
        plat = sys_platform()
        if plat == "win":
            os.startfile(file_path)  # type: ignore[attr-defined]
        elif plat == "mac":
            subprocess.run(["open", file_path], check=False)
        else:
            subprocess.run(["xdg-open", file_path], check=False)
    except Exception:
        pass


def lbl(parent, text, size=11, bold=False, bg=BG, fg=TEXT):
    return tk.Label(
        parent,
        text=text,
        bg=bg,
        fg=fg,
        font=(FONT, size, "bold" if bold else "normal")
    )


class FlatButton(tk.Frame):
    def __init__(self, parent, text, command, bg=ACCENT, fg="#FFFFFF", height=44):
        super().__init__(parent, bg=bg, height=height, cursor="hand2")
        self.command = command
        self.pack_propagate(False)

        self.label = tk.Label(
            self,
            text=text,
            bg=bg,
            fg=fg,
            font=(FONT, 11, "bold"),
            cursor="hand2"
        )
        self.label.pack(fill="both", expand=True)

        self.bind("<Button-1>", self._click)
        self.label.bind("<Button-1>", self._click)

    def _click(self, _event=None):
        if self.command:
            self.command()

    def config_colors(self, bg, fg):
        self.configure(bg=bg)
        self.label.configure(bg=bg, fg=fg)


class InputField(tk.Frame):
    def __init__(self, parent, show=None):
        super().__init__(parent, bg=BORDER, height=43)
        self.pack_propagate(False)

        inner = tk.Frame(self, bg=FIELD_BG)
        inner.pack(fill="both", expand=True, padx=1, pady=1)

        self.entry = tk.Entry(
            inner,
            show=show,
            bg=FIELD_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=(FONT, 12)
        )
        self.entry.pack(fill="both", expand=True, padx=12, pady=8)

    def get(self):
        return self.entry.get()

    def focus(self):
        self.entry.focus()

    def bind(self, sequence=None, func=None, add=None):
        return self.entry.bind(sequence, func, add)


def make_button(parent, text, command, bg=ACCENT, fg="#FFFFFF"):
    return FlatButton(parent, text, command, bg, fg)


def make_entry(parent, show=None):
    return InputField(parent, show=show)


class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Photo Vault")
        self.geometry("1150x720")
        self.minsize(1050, 680)
        self.configure(bg=BG)

        try:
            self.tk.call("tk", "scaling", 1.0)
        except Exception:
            pass

        db.init_db()
        self.session: auth.Session | None = None

        self.container = tk.Frame(self, bg=BG)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        for F in (AuthFrame, VaultFrame):
            frame = F(self.container, self)
            self.frames[F.__name__] = frame
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.show_frame("AuthFrame")

    def show_frame(self, name: str):
        self.frames[name].tkraise()


class AuthFrame(tk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, bg=BG)
        self.app = app

        self.build_sidebar()
        self.build_card()
        self.show_login()

    def build_sidebar(self):
        side = tk.Frame(self, bg=SIDEBAR, width=330)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        lbl(side, "PHOTO VAULT", 24, True, SIDEBAR, "#FFFFFF").pack(pady=(105, 8))
        lbl(side, "Сигурно. Лично. Криптирано.", 12, False, SIDEBAR, "#CBD5E1").pack(pady=(0, 55))

        features = [
            ("AES-GCM криптиране", "Изображенията се съхраняват криптирани."),
            ("Argon2id защита", "Сигурно извличане на ключове от парола."),
            ("NIST политика за пароли", "Минимум 15 символа и проверки за сигурност."),
            ("Двуфакторна автентикация", "Входът изисква 6-цифрен код."),
        ]

        for title, desc in features:
            box = tk.Frame(side, bg=SIDEBAR)
            box.pack(fill="x", padx=45, pady=14)

            lbl(box, title, 12, True, SIDEBAR, "#FFFFFF").pack(anchor="w")
            lbl(box, desc, 10, False, SIDEBAR, "#CBD5E1").pack(anchor="w", pady=(3, 0))

        lbl(side, "Вашата поверителност е наш приоритет.", 11, False, SIDEBAR, "#A5B4FC").pack(side="bottom", pady=40)

    def build_card(self):
        self.card = tk.Frame(self, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        self.card.place(relx=0.62, rely=0.5, anchor="center", width=690, height=630)

        tabs = tk.Frame(self.card, bg=CARD)
        tabs.pack(fill="x", padx=50, pady=(24, 0))

        self.login_tab = FlatButton(tabs, "Вход"
                                          "", self.show_login, bg=CARD, fg=ACCENT, height=36)
        self.login_tab.pack(side="left", expand=True, fill="x", padx=(0, 6))

        self.register_tab = FlatButton(tabs, "Регистрация", self.show_register, bg=CARD, fg=MUTED, height=36)
        self.register_tab.pack(side="left", expand=True, fill="x", padx=(6, 0))

        tk.Frame(self.card, bg=BORDER, height=1).pack(fill="x", pady=(16, 0))

        self.body = tk.Frame(self.card, bg=CARD)
        self.body.pack(fill="both", expand=True, padx=55, pady=26)

    def set_active_tab(self, mode):
        if mode == "login":
            self.login_tab.config_colors(LIGHT_BTN, ACCENT_DARK)
            self.register_tab.config_colors(CARD, MUTED)
        else:
            self.login_tab.config_colors(CARD, MUTED)
            self.register_tab.config_colors(LIGHT_BTN, ACCENT_DARK)

    def clear_body(self):
        for w in self.body.winfo_children():
            w.destroy()

    def form_field(self, parent, title, show=None):
        lbl(parent, title, 10, True, CARD, TEXT).pack(anchor="w", pady=(7, 3))
        e = make_entry(parent, show=show)
        e.pack(fill="x")
        return e

    def show_login(self):
        self.clear_body()
        self.set_active_tab("login")

        lbl(self.body, "Добре дошли!", 25, True, CARD, TEXT).pack(anchor="w")
        lbl(self.body, "Влезте с паролата си и кода за двуфакторна автентикация.", 12, False, CARD, MUTED).pack(anchor="w", pady=(6, 28))

        self.login_username = self.form_field(self.body, "Потребителско име")
        self.login_password = self.form_field(self.body, "Основна парола", show="*")

        make_button(self.body, "Вход", self.on_login).pack(fill="x", pady=(30, 16))

        link = tk.Label(
            self.body,
            text="Нямате профил? Регистрирайте се тук",
            bg=CARD,
            fg=ACCENT,
            font=(FONT, 11, "bold"),
            cursor="hand2"
        )
        link.pack()
        link.bind("<Button-1>", lambda _e: self.show_register())

        self.login_password.bind("<Return>", lambda _e: self.on_login())

    def show_register(self):
        self.clear_body()
        self.set_active_tab("register")

        lbl(self.body, "Създаване на профил", 21, True, CARD, TEXT).pack(anchor="w")
        lbl(self.body, "Създайте профил с NIST защита на паролата.", 11, False, CARD, MUTED).pack(anchor="w", pady=(5, 10))

        grid = tk.Frame(self.body, bg=CARD)
        grid.pack(fill="x")

        left = tk.Frame(grid, bg=CARD)
        right = tk.Frame(grid, bg=CARD)

        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))

        self.first_name = self.form_field(left, "Име")
        self.last_name = self.form_field(right, "Фамилия")

        self.email = self.form_field(left, "Имейл")
        self.reg_username = self.form_field(right, "Потребителско име")

        self.reg_password = self.form_field(left, "Основна парола", show="*")
        self.reg_repeat = self.form_field(right, "Потвърди паролата", show="*")

        checks = tk.Frame(self.body, bg="#F3F4FF")
        checks.pack(fill="x", pady=(14, 12))

        for text in [
            "✓ Минимум 15 символа",
            "✓ Паролата не трябва да съдържа потребителското име",
            "✓ Ще бъде активирана двуфакторна автентикация",
        ]:
            lbl(checks, text, 10, False, "#F3F4FF", ACCENT_DARK).pack(anchor="w", padx=18, pady=3)

        make_button(self.body, "Създай профил", self.on_register).pack(fill="x", pady=(4, 9))

        link = tk.Label(
            self.body,
            text="Вече имате профил? Влезте тук",
            bg=CARD,
            fg=ACCENT,
            font=(FONT, 11, "bold"),
            cursor="hand2"
        )
        link.pack()
        link.bind("<Button-1>", lambda _e: self.show_login())

    def on_register(self):
        if self.reg_password.get() != self.reg_repeat.get():
            messagebox.showerror("Грешка", "Паролите не съвпадат.")
            return

        try:
            self.app.session = auth.register(
                self.first_name.get().strip(),
                self.last_name.get().strip(),
                self.email.get().strip(),
                self.reg_username.get().strip(),
                self.reg_password.get()
            )

            secret = auth.get_totp_secret(self.reg_username.get().strip())

            messagebox.showinfo(
                "Настройка на двуфакторна автентикация",
                "Профилът е създаден успешно.\n\n"
                "Add this key in Google Authenticator or Microsoft Authenticator:\n\n"
                f"{secret}\n\n"
                "След това използвайте генерирания 6-цифрен код при вход."
            )

            self.app.frames["VaultFrame"].refresh()
            self.app.show_frame("VaultFrame")

        except Exception as e:
            messagebox.showerror("Грешка", str(e))

    def two_factor_popup(self, username: str) -> bool:
        secret = auth.get_totp_secret(username)

        if not secret:
            messagebox.showerror("Грешка при 2FA" "Липсва конфигурация за двуфакторна автентикация.")
            return False

        win = tk.Toplevel(self)
        win.title("Двуфакторна автентикация")
        win.geometry("430x260")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.grab_set()

        card = tk.Frame(win, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="both", expand=True, padx=24, pady=24)

        lbl(card, "Двуфакторна автентикация", 18, True, CARD, TEXT).pack(pady=(24, 8))
        lbl(card, "Въведете 6-цифрения код от приложението за удостоверяване.", 10, False, CARD, MUTED).pack()

        code_entry = make_entry(card)
        code_entry.pack(fill="x", padx=45, pady=18)

        result = {"ok": False}

        def check():
            if auth.verify_totp_code(secret, code_entry.get()):
                result["ok"] = True
                win.destroy()
            else:
                messagebox.showerror("Отказан достъп", "Невалиден 2FA код.")

        make_button(card, "Потвърди кода", check).pack(fill="x", padx=45)

        code_entry.focus()
        win.wait_window()

        return result["ok"]

    def on_login(self):
        try:
            session = auth.login(
                self.login_username.get().strip(),
                self.login_password.get()
            )

            if not self.two_factor_popup(session.username):
                return

            self.app.session = session
            self.app.frames["VaultFrame"].refresh()
            self.app.show_frame("VaultFrame")

        except Exception as e:
            messagebox.showerror("Грешка", str(e))


class VaultFrame(tk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, bg=BG)
        self.app = app
        self._id_map: list[int] = []

        self.build_layout()

    def build_layout(self):
        side = tk.Frame(self, bg=SIDEBAR, width=225)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        lbl(side, "PHOTO VAULT", 16, True, SIDEBAR, "#FFFFFF").pack(anchor="w", padx=28, pady=(42, 35))

        self.side_button(side, "Моят фотоархив", self.refresh)
        self.side_button(side, "Добави изображение", self.add_image)
        self.side_button(side, "Смяна на парола", self.change_password)
        self.side_button(side, "Изход", self.logout)

        self.lbl_user = lbl(side, "User: -", 10, False, SIDEBAR, "#CBD5E1")
        self.lbl_user.pack(side="bottom", anchor="w", padx=28, pady=28)

        main = tk.Frame(self, bg=BG)
        main.pack(side="left", fill="both", expand=True, padx=35, pady=32)

        top = tk.Frame(main, bg=BG)
        top.pack(fill="x")

        title_box = tk.Frame(top, bg=BG)
        title_box.pack(side="left")

        lbl(title_box, "Моят фотоархив", 25, True, BG, TEXT).pack(anchor="w")
        lbl(title_box, "Вашите криптирани изображения", 11, False, BG, MUTED).pack(anchor="w", pady=(4, 0))

        content = tk.Frame(main, bg=BG)
        content.pack(fill="both", expand=True, pady=(25, 0))

        list_card = tk.Frame(content, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        list_card.pack(side="left", fill="both", expand=True, padx=(0, 20))

        self.listbox = tk.Listbox(
            list_card,
            bg=CARD,
            fg=TEXT,
            selectbackground=LIGHT_BTN,
            selectforeground=TEXT,
            font=(FONT, 13),
            relief="flat",
            bd=0,
            highlightthickness=0,
            activestyle="none"
        )
        self.listbox.pack(fill="both", expand=True, padx=24, pady=24)

        actions = tk.Frame(content, bg=CARD, width=245, highlightbackground=BORDER, highlightthickness=1)
        actions.pack(side="right", fill="y")
        actions.pack_propagate(False)

        lbl(actions, "Бързи действия", 15, True, CARD, TEXT).pack(anchor="w", padx=24, pady=(30, 18))

        make_button(actions, "Добави изображение", self.add_image, bg=LIGHT_BTN, fg=ACCENT_DARK).pack(fill="x", padx=24, pady=8)
        make_button(actions, "Преглед", self.preview, bg=LIGHT_BTN, fg=ACCENT_DARK).pack(fill="x", padx=24, pady=8)
        make_button(actions, "Експортирай", self.export_decrypted, bg=LIGHT_BTN, fg=ACCENT_DARK).pack(fill="x", padx=24, pady=8)
        make_button(actions, "Изтрий", self.delete_image, bg=DANGER_BG, fg=DANGER).pack(fill="x", padx=24, pady=8)

        info = tk.Frame(actions, bg="#F9FAFB")
        info.pack(fill="x", padx=24, pady=(25, 0))

        lbl(info, "Контрол на достъпа", 11, True, "#F9FAFB", TEXT).pack(anchor="w", padx=12, pady=(10, 3))
        lbl(info, "Прегледът изисква парола.", 9, False, "#F9FAFB", MUTED).pack(anchor="w", padx=12)
        lbl(info, "Експортирането изисква парола.", 9, False, "#F9FAFB", MUTED).pack(anchor="w", padx=12, pady=(0, 10))

        self.footer = lbl(main, "Всички файлове са криптирани.", 10, False, BG, MUTED)
        self.footer.pack(anchor="w", pady=(18, 0))

    def side_button(self, parent, text, command):
        b = FlatButton(parent, text, command, bg=SIDEBAR, fg="#E5E7EB", height=42)
        b.pack(fill="x", padx=14, pady=4)

    def require_session(self):
        if not self.app.session:
            raise RuntimeError("Not logged in")
        return self.app.session

    def logout(self):
        self.app.session = None
        self.app.show_frame("AuthFrame")

    def refresh(self):
        sess = self.require_session()

        self.lbl_user.config(text=f"Потребител: {sess.username}")
        self.listbox.delete(0, tk.END)
        self._id_map = []

        for it in vault.list_images(sess):
            self._id_map.append(it["id"])
            self.listbox.insert(
                tk.END,
                f'#{it["id"]}    {it["original_name"]}    |    {it["created_at"]}'
            )

        self.footer.config(
            text=f"Общо изображения: {len(self._id_map)}    |    Всички файлове са криптирани."
        )

    def selected_image_id(self):
        sel = self.listbox.curselection()
        return None if not sel else self._id_map[sel[0]]

    def password_popup(self, title, text):
        sess = self.require_session()

        win = tk.Toplevel(self)
        win.title(title)
        win.geometry("430x260")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.grab_set()

        card = tk.Frame(win, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="both", expand=True, padx=24, pady=24)

        lbl(card, title, 20, True, CARD, TEXT).pack(pady=(25, 8))
        lbl(card, text, 11, True, CARD, TEXT).pack()

        pass_entry = make_entry(card, show="*")
        pass_entry.pack(fill="x", padx=45, pady=18)

        result = {"ok": False}

        def check():
            ok = auth.verify_password(sess.username, pass_entry.get())

            if ok:
                result["ok"] = True
                win.destroy()
            else:
                messagebox.showerror("Отказан достъп", "Невалидна парола.")

        make_button(card, "Продължи", check).pack(fill="x", padx=45)

        pass_entry.focus()
        win.wait_window()

        return result["ok"]

    def add_image(self):
        sess = self.require_session()

        fp = filedialog.askopenfilename(
            title="Изберете изображение",
            filetypes=[
                ("Images", "*.jpg *.jpeg *.png *.webp *.bmp *.gif"),
                ("All files", "*.*")
            ]
        )

        if fp:
            try:
                image_id = vault.add_image(sess, fp)
                messagebox.showinfo("Успех", f"Изображението е добавено и криптирано. ID: {image_id}")
                self.refresh()

            except Exception as e:
                messagebox.showerror("Грешка", str(e))

    def preview(self):
        sess = self.require_session()
        img_id = self.selected_image_id()

        if img_id is None:
            messagebox.showwarning("Избор", "Избери снимка от списъка.")
            return

        if not self.password_popup(
            "Преглед на изображение",
            "Въведете паролата си за преглед:"
        ):
            return

        try:
            data, name = vault.decrypt_image_to_bytes(sess, img_id)

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=Path(name).suffix,
                prefix="vault_preview_"
            ) as f:
                f.write(data)
                open_with_default_app(f.name)

        except Exception as e:
            messagebox.showerror("Грешка", str(e))

    def export_decrypted(self):
        sess = self.require_session()
        img_id = self.selected_image_id()

        if img_id is None:
            messagebox.showwarning("Избор", "Избери снимка от списъка.")
            return

        if not self.password_popup(
            "Експортиране на изображение",
            "Въведете паролата си за експортиране:"
        ):
            return

        out = filedialog.askdirectory(title="Изберете папка за експортиране")

        if out:
            try:
                path = vault.export_decrypted(sess, img_id, out)
                messagebox.showinfo("Успех", f"Изображението е експортирано в:\n{path}")
            except Exception as e:
                messagebox.showerror("Грешка", str(e))

    def delete_image(self):
        sess = self.require_session()
        img_id = self.selected_image_id()

        if img_id is None:
            messagebox.showwarning("Избор", "Избери снимка от списъка.")
            return

        if not messagebox.askyesno("Потвърждение", f"Да изтрия ли снимка ID={img_id}?"):
            return

        try:
            if vault.delete_image(sess, img_id):
                self.refresh()

        except Exception as e:
            messagebox.showerror("Грешка", str(e))

    def change_password(self):
        sess = self.require_session()

        win = tk.Toplevel(self)
        win.title("Смяна на парола")
        win.geometry("500x525")
        win.configure(bg=BG)
        win.resizable(False, False)

        card = tk.Frame(win, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="both", expand=True, padx=28, pady=28)

        lbl(card, "Смяна на парола", 23, True, CARD, TEXT).pack(anchor="w", padx=35, pady=(28, 5))
        lbl(card, f"Потребител: {sess.username}", 12, False, CARD, MUTED).pack(anchor="w", padx=35, pady=(0, 20))

        def field(title):
            lbl(card, title, 11, True, CARD, TEXT).pack(anchor="w", padx=35, pady=(9, 4))
            e = make_entry(card, show="*")
            e.pack(fill="x", padx=35)
            return e

        old_e = field("Текуща парола")
        new_e = field("Нова парола")
        rep_e = field("Потвърди новата парола")

        checks = tk.Frame(card, bg="#F3F4FF")
        checks.pack(fill="x", padx=35, pady=18)

        for text in [
            "✓ Минимум 15 символа",
            "✓ Всички ключове се прекриптират автоматично",
            "✓ Двуфакторната защита остава активна"
        ]:
            lbl(checks, text, 10, False, "#F3F4FF", ACCENT_DARK).pack(anchor="w", padx=15, pady=3)

        def do_change():
            if new_e.get() != rep_e.get():
                messagebox.showerror("Грешка", "Новите пароли не съвпадат.")
                return

            try:
                auth.change_password(sess.username, old_e.get(), new_e.get())
                messagebox.showinfo("Успех", "Паролата е сменена успешно.")
                win.destroy()

            except Exception as e:
                messagebox.showerror("Грешка", str(e))

        make_button(card, "Смяна на парола", do_change).pack(fill="x", padx=35, pady=(4, 0))


def run_gui():
    App().mainloop()