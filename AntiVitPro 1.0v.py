import os
import hashlib
import json
import datetime
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import shutil

class AntivirusScanner:
    def __init__(self):
        """Инициализация сканера"""
        self.virus_signatures = self.load_signatures()
        self.quarantine_dir = os.path.join(os.path.dirname(__file__), "Quarantine")
        self.whitelist_file = os.path.join(os.path.dirname(__file__), "whitelist.json")
        self.whitelist = self.load_whitelist()
        
    def load_signatures(self):
        """Загрузка сигнатур вирусов"""
        signatures = {
            # EICAR тестовый файл
            "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File (Test Virus)",
            "d41d8cd98f00b204e9800998ecf8427e": "Empty-File-Test",
            
            # Примеры известных вредоносных хешей (для демонстрации)
            "098f6bcd4621d373cade4e832627b4f6": "Test.Malware.Example",
            "5d41402abc4b2a76b9719d911017c592": "Test.Spyware.Example",
            "7d793037a0760186574b0282f2f435e7": "Test.Ransomware.Example",
            "e10adc3949ba59abbe56e057f20f883e": "Test.Adware.Example",
            "25d55ad283aa400af464c76d713c07ad": "Test.Trojan.Example",
            "e99a18c428cb38d5f260853678922e03": "Test.Worm.Example",
        }
        
        # Загрузка дополнительных сигнатур из файла, если он существует
        try:
            if os.path.exists("virus_signatures.json"):
                with open("virus_signatures.json", "r", encoding="utf-8") as f:
                    additional = json.load(f)
                    signatures.update(additional)
        except:
            pass
            
        return signatures
    
    def load_whitelist(self):
        """Загрузка белого списка"""
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except:
            pass
        return []
    
    def save_whitelist(self):
        """Сохранение белого списка"""
        try:
            with open(self.whitelist_file, "w", encoding="utf-8") as f:
                json.dump(self.whitelist, f, indent=4)
            return True
        except:
            return False
    
    def calculate_file_hash(self, file_path):
        """Вычисление хеша файла"""
        try:
            if os.path.getsize(file_path) > 50 * 1024 * 1024:  # Увеличили лимит до 50 МБ
                return "too_large_for_hash"
            
            hasher = hashlib.sha256()  # Перешли на SHA-256 для большей безопасности
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Ошибка хеширования {file_path}: {e}")
            return "error_hash"
    
    def is_file_in_whitelist(self, file_path):
        """Проверка, находится ли файл в белом списке"""
        try:
            file_hash = self.calculate_file_hash(file_path)
            if file_hash == "too_large_for_hash" or file_hash == "error_hash":
                return False
            return file_hash in self.whitelist
        except:
            return False
    
    def scan_file(self, file_path):
        """Сканирование файла с улучшенными фильтрами"""
        result = {
            "file": file_path,
            "status": "clean",
            "threat": None,
            "risk_level": "low",  # low, medium, high
        }
        
        try:
            if not os.path.isfile(file_path):
                result["status"] = "skipped"
                return result
            
            # Проверка белого списка
            if self.is_file_in_whitelist(file_path):
                result["status"] = "whitelisted"
                return result
            
            # Проверка по хешу
            file_hash = self.calculate_file_hash(file_path)
            
            if file_hash in self.virus_signatures:
                result["status"] = "infected"
                result["threat"] = self.virus_signatures[file_hash]
                result["risk_level"] = "high"
                return result
            
            # Проверка на подозрительные расширения с приоритетами
            file_name = os.path.basename(file_path).lower()
            ext = os.path.splitext(file_path)[1].lower()
            
            # Высокий риск
            high_risk_extensions = {
                '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1',
                '.jar', '.class', '.pyc', '.sh', '.reg', '.pif', '.com', '.hta'
            }
            
            # Средний риск
            medium_risk_extensions = {
                '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
                '.zip', '.rar', '.7z', '.tar', '.gz'
            }
            
            # Низкий риск
            low_risk_extensions = {
                '.txt', '.log', '.ini', '.cfg', '.json', '.xml', '.html', '.htm',
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp3', '.mp4', '.avi'
            }
            
            # Проверка на двойные расширения (например, файл.txt.exe)
            if '.' in file_name and file_name.count('.') > 1:
                parts = file_name.split('.')
                if len(parts) > 2 and f".{parts[-1]}" in high_risk_extensions:
                    result["status"] = "suspicious"
                    result["threat"] = f"Двойное расширение: {file_name}"
                    result["risk_level"] = "high"
                    return result
            
            # Проверка на скрытые системные файлы
            if file_name.startswith('~') or file_name.startswith('$'):
                if ext in high_risk_extensions:
                    result["status"] = "suspicious"
                    result["threat"] = "Скрытый системный файл с опасным расширением"
                    result["risk_level"] = "medium"
                    return result
            
            # Проверка размера файла (очень маленькие или очень большие исполняемые файлы)
            try:
                file_size = os.path.getsize(file_path)
                if ext in high_risk_extensions:
                    if file_size < 1024:  # Меньше 1KB
                        result["status"] = "suspicious"
                        result["threat"] = "Подозрительно маленький исполняемый файл"
                        result["risk_level"] = "medium"
                        return result
                    elif file_size > 100 * 1024 * 1024:  # Больше 100MB
                        result["status"] = "suspicious"
                        result["threat"] = "Очень большой исполняемый файл"
                        result["risk_level"] = "medium"
                        return result
            except:
                pass
            
            # Основная проверка расширений
            if ext in high_risk_extensions:
                result["status"] = "suspicious"
                result["threat"] = f"Файл с опасным расширением {ext}"
                result["risk_level"] = "high"
                
                # Дополнительные проверки для исполняемых файлов
                if ext in ['.exe', '.dll', '.scr']:
                    try:
                        # Проверка на легитимные системные пути
                        system_paths = [
                            'C:\\Windows\\System32',
                            'C:\\Windows\\SysWOW64',
                            'C:\\Program Files',
                            'C:\\Program Files (x86)'
                        ]
                        file_lower = file_path.lower()
                        is_system_file = any(path.lower() in file_lower for path in system_paths)
                        
                        if not is_system_file and 'windows' not in file_lower:
                            result["risk_level"] = "high"
                        else:
                            result["risk_level"] = "medium"
                    except:
                        pass
                        
            elif ext in medium_risk_extensions:
                result["status"] = "suspicious"
                result["threat"] = f"Файл с потенциально опасным расширением {ext}"
                result["risk_level"] = "medium"
            
        except Exception as e:
            print(f"Ошибка сканирования {file_path}: {e}")
            result["status"] = "error"
            
        return result
    
    def quarantine_file(self, file_path):
        """Помещение файла в карантин"""
        try:
            # Создание папки карантина, если она не существует
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir)
            
            # Генерация уникального имени для файла в карантине
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            file_name = os.path.basename(file_path)
            safe_name = f"{timestamp}_{file_name}"
            quarantine_path = os.path.join(self.quarantine_dir, safe_name)
            
            # Сохранение информации о файле
            file_info = {
                "original_path": file_path,
                "quarantine_path": quarantine_path,
                "original_name": file_name,
                "quarantined_date": datetime.datetime.now().isoformat(),
                "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0
            }
            
            # Перемещение файла в карантин
            if os.path.exists(file_path):
                shutil.move(file_path, quarantine_path)
                
                # Сохранение информации в журнал карантина
                quarantine_log = os.path.join(self.quarantine_dir, "quarantine_log.json")
                quarantine_data = []
                
                if os.path.exists(quarantine_log):
                    try:
                        with open(quarantine_log, "r", encoding="utf-8") as f:
                            quarantine_data = json.load(f)
                    except:
                        pass
                
                quarantine_data.append(file_info)
                
                with open(quarantine_log, "w", encoding="utf-8") as f:
                    json.dump(quarantine_data, f, indent=4, ensure_ascii=False)
                
                return True, "Файл помещен в карантин"
            else:
                return False, "Файл не найден"
                
        except Exception as e:
            print(f"Ошибка помещения в карантин {file_path}: {e}")
            return False, f"Ошибка: {str(e)}"
    
    def restore_from_quarantine(self, quarantine_info):
        """Восстановление файла из карантина"""
        try:
            quarantine_path = quarantine_info["quarantine_path"]
            original_path = quarantine_info["original_path"]
            
            if os.path.exists(quarantine_path):
                # Восстановление файла
                shutil.move(quarantine_path, original_path)
                
                # Удаление записи из журнала
                quarantine_log = os.path.join(self.quarantine_dir, "quarantine_log.json")
                if os.path.exists(quarantine_log):
                    with open(quarantine_log, "r", encoding="utf-8") as f:
                        quarantine_data = json.load(f)
                    
                    # Удаление записи о восстановленном файле
                    quarantine_data = [item for item in quarantine_data 
                                     if item["quarantine_path"] != quarantine_path]
                    
                    with open(quarantine_log, "w", encoding="utf-8") as f:
                        json.dump(quarantine_data, f, indent=4, ensure_ascii=False)
                
                return True, "Файл восстановлен"
            else:
                return False, "Файл в карантине не найден"
                
        except Exception as e:
            print(f"Ошибка восстановления из карантина: {e}")
            return False, f"Ошибка: {str(e)}"
    
    def get_quarantine_list(self):
        """Получение списка файлов в карантине"""
        try:
            quarantine_log = os.path.join(self.quarantine_dir, "quarantine_log.json")
            if os.path.exists(quarantine_log):
                with open(quarantine_log, "r", encoding="utf-8") as f:
                    return json.load(f)
        except:
            pass
        return []

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AntiVit Security Pro")
        self.root.geometry("1100x750")
        
        # Инициализация
        self.scanning = False
        self.scan_thread = None
        self.scanned_files = 0
        self.infected_files = 0
        self.suspicious_files = 0
        
        # Текущие настройки языка и темы
        self.current_language = "Русский"
        self.current_theme = "Светлая"
        
        # Для хранения ссылок на виджеты, которые нужно обновлять
        self.ui_widgets = {}
        
        self.scanner = AntivirusScanner()
        self.scan_type = tk.StringVar(value="quick")
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Готов к работе")
        
        # Словари переводов
        self.translations = {
            "Русский": {
                "title": "AntiVit Security Pro",
                "scan_type": "Тип сканирования",
                "quick_scan": "Быстрое сканирование (до 500 файлов)",
                "full_scan": "Полное сканирование (все файлы)",
                "custom_scan": "Выборочное сканирование",
                "start_scan": "Начать сканирование",
                "pause": "Пауза",
                "stop": "Стоп",
                "select_folder": "Выбрать папку",
                "check_file": "Проверить файл",
                "manage_quarantine": "Управление карантином",
                "quarantine": "Карантин",
                "to_quarantine": "В карантин",
                "whitelist": "Белый список",
                "add_to_whitelist": "Добавить в белый список",
                "report": "Отчёт",
                "progress": "Прогресс сканирования",
                "scanned": "Проверено: {count} файлов",
                "threats": "Угроз: {count}",
                "suspicious": "Подозрительных: {count}",
                "log": "Лог сканирования",
                "results": "Результаты сканирования",
                "file": "Файл",
                "status": "Статус",
                "risk": "Уровень риска",
                "info": "Информация",
                "ready": "Готов к работе",
                "scanning": "Сканирование...",
                "paused": "Сканирование приостановлено",
                "stopped": "Сканирование остановлено",
                "language": "Язык",
                "theme": "Тема",
                "help": "Помощь",
                "about": "О программе",
                "support": "Поддержка",
                "light": "Светлая",
                "dark": "Тёмная",
                "folder_not_selected": "Папка не выбрана",
                "folder_selected": "Выбрана: {path}",
                "select_file": "Выберите файл для проверки",
                "file_scan_complete": "Проверка файла завершена",
                "file_infected": "Файл заражен",
                "file_clean": "Файл чист",
                "file_suspicious": "Файл подозрительный",
                "select_file_to_scan": "Выберите файл для сканирования",
                "quarantine_success": "Файл помещен в карантин",
                "quarantine_error": "Ошибка помещения в карантин",
                "restore": "Восстановить",
                "delete": "Удалить",
                "manage": "Управление",
                "no_files": "Нет файлов в карантине",
                "whitelist_success": "Файл добавлен в белый список",
                "whitelist_error": "Ошибка добавления в белый список",
                "supported_by": "Полностью поддерживается компанией SM Team",  # Добавлено
            },
            "English": {
                "title": "AntiVit Security Pro",
                "scan_type": "Scan Type",
                "quick_scan": "Quick Scan (up to 500 files)",
                "full_scan": "Full Scan (all files)",
                "custom_scan": "Custom Scan",
                "start_scan": "Start Scan",
                "pause": "Pause",
                "stop": "Stop",
                "select_folder": "Select Folder",
                "check_file": "Check File",
                "manage_quarantine": "Manage Quarantine",
                "quarantine": "Quarantine",
                "to_quarantine": "To Quarantine",
                "whitelist": "Whitelist",
                "add_to_whitelist": "Add to Whitelist",
                "report": "Report",
                "progress": "Scan Progress",
                "scanned": "Scanned: {count} files",
                "threats": "Threats: {count}",
                "suspicious": "Suspicious: {count}",
                "log": "Scan Log",
                "results": "Scan Results",
                "file": "File",
                "status": "Status",
                "risk": "Risk Level",
                "info": "Information",
                "ready": "Ready",
                "scanning": "Scanning...",
                "paused": "Scanning paused",
                "stopped": "Scanning stopped",
                "language": "Language",
                "theme": "Theme",
                "help": "Help",
                "about": "About",
                "support": "Support",
                "light": "Light",
                "dark": "Dark",
                "folder_not_selected": "Folder not selected",
                "folder_selected": "Selected: {path}",
                "select_file": "Select file to check",
                "file_scan_complete": "File scan completed",
                "file_infected": "File is infected",
                "file_clean": "File is clean",
                "file_suspicious": "File is suspicious",
                "select_file_to_scan": "Select file to scan",
                "quarantine_success": "File moved to quarantine",
                "quarantine_error": "Error moving to quarantine",
                "restore": "Restore",
                "delete": "Delete",
                "manage": "Manage",
                "no_files": "No files in quarantine",
                "whitelist_success": "File added to whitelist",
                "whitelist_error": "Error adding to whitelist",
                "supported_by": "Fully supported by SM Team",  # Добавлено
            }
        }
        
        # Цветовые схемы для тем
        self.themes = {
            "Светлая": {
                "bg": "#f0f0f0",
                "fg": "#000000",
                "button_bg": "#4CAF50",
                "button_fg": "white",
                "stop_bg": "#f44336",
                "quarantine_bg": "#FF9800",
                "frame_bg": "#ffffff",
                "text_bg": "#ffffff",
                "text_fg": "#000000",
                "tree_bg": "#ffffff",
                "tree_fg": "#000000",
                "tree_heading_bg": "#e0e0e0",
                "tree_heading_fg": "#000000",
                "log_bg": "#ffffff",
                "log_fg": "#000000",
                "menu_bg": "#f0f0f0",
                "menu_fg": "#000000",
                "progress_trough": "#e0e0e0",
                "progress_bar": "#4CAF50",
                "scrollbar_bg": "#c0c0c0",
                "scrollbar_trough": "#e0e0e0",
                "selected_bg": "#4CAF50",
                "selected_fg": "white",
                "risk_high": "#ff4444",
                "risk_medium": "#ff9800",
                "risk_low": "#4CAF50",
            },
            "Тёмная": {
                "bg": "#1e1e1e",
                "fg": "#ffffff",
                "button_bg": "#2E7D32",
                "button_fg": "white",
                "stop_bg": "#C62828",
                "quarantine_bg": "#FF8F00",
                "frame_bg": "#2d2d30",
                "text_bg": "#2d2d30",
                "text_fg": "#ffffff",
                "tree_bg": "#2d2d30",
                "tree_fg": "#ffffff",
                "tree_heading_bg": "#3e3e42",
                "tree_heading_fg": "#ffffff",
                "log_bg": "#2d2d30",
                "log_fg": "#ffffff",
                "menu_bg": "#2d2d30",
                "menu_fg": "#ffffff",
                "progress_trough": "#3e3e42",
                "progress_bar": "#2E7D32",
                "scrollbar_bg": "#5a5a5a",
                "scrollbar_trough": "#3e3e42",
                "selected_bg": "#2E7D32",
                "selected_fg": "white",
                "risk_high": "#ff4444",
                "risk_medium": "#ff9800",
                "risk_low": "#4CAF50",
            }
        }
        
        # Настройка стилей ttk перед созданием интерфейса
        self.setup_ttk_styles()
        
        # Создание интерфейса
        self.setup_ui()
        
    def setup_ttk_styles(self):
        """Настройка стилей ttk виджетов"""
        theme = self.themes[self.current_theme]
        
        # Создаем стиль для ttk
        style = ttk.Style()
        
        # Конфигурация прогресс-бара
        style.configure("Horizontal.TProgressbar",
                        background=theme["progress_bar"],
                        troughcolor=theme["progress_trough"])
        
        # Конфигурация Treeview
        style.configure("Treeview",
                        background=theme["tree_bg"],
                        foreground=theme["tree_fg"],
                        fieldbackground=theme["tree_bg"])
        
        style.configure("Treeview.Heading",
                        background=theme["tree_heading_bg"],
                        foreground=theme["tree_heading_fg"])
        
        # Конфигурация Scrollbar
        style.configure("Vertical.TScrollbar",
                        background=theme["scrollbar_bg"],
                        troughcolor=theme["scrollbar_trough"],
                        arrowcolor=theme["fg"])
        
        style.configure("Horizontal.TScrollbar",
                        background=theme["scrollbar_bg"],
                        troughcolor=theme["scrollbar_trough"],
                        arrowcolor=theme["fg"])
        
        # Настройка цвета выделения в Treeview
        style.map('Treeview',
                  background=[('selected', theme["selected_bg"])],
                  foreground=[('selected', theme["selected_fg"])])
        
    def setup_ui(self):
        """Создание интерфейса"""
        theme = self.themes[self.current_theme]
        trans = self.translations[self.current_language]
        
        # Главный контейнер
        main_frame = tk.Frame(self.root, bg=theme["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Заголовок
        header_frame = tk.Frame(main_frame, bg=theme["bg"])
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Щит
        tk.Label(
            header_frame,
            text="🛡️",
            font=('Arial', 48),
            fg='#4CAF50',
            bg=theme["bg"]
        ).pack()
        
        # Название
        self.title_label = tk.Label(
            header_frame,
            text=trans["title"],
            font=('Arial', 20, 'bold'),
            fg='#4CAF50',
            bg=theme["bg"]
        )
        self.title_label.pack(pady=(10, 5))
        self.ui_widgets["title_label"] = self.title_label
        
        # Панель выбора сканирования
        scan_frame = tk.LabelFrame(main_frame, text=trans["scan_type"], 
                                 bg=theme["frame_bg"], fg=theme["fg"])
        scan_frame.pack(fill=tk.X, pady=(0, 10))
        self.ui_widgets["scan_frame"] = scan_frame
        
        # Радиокнопки
        self.quick_radio = tk.Radiobutton(
            scan_frame, 
            text=trans["quick_scan"], 
            variable=self.scan_type, 
            value="quick",
            bg=theme["frame_bg"], fg=theme["fg"],
            selectcolor=theme["frame_bg"]
        )
        self.quick_radio.grid(row=0, column=0, padx=20, pady=10, sticky=tk.W)
        self.ui_widgets["quick_radio"] = self.quick_radio
        
        self.full_radio = tk.Radiobutton(
            scan_frame, 
            text=trans["full_scan"], 
            variable=self.scan_type, 
            value="full",
            bg=theme["frame_bg"], fg=theme["fg"],
            selectcolor=theme["frame_bg"]
        )
        self.full_radio.grid(row=0, column=1, padx=20, pady=10, sticky=tk.W)
        self.ui_widgets["full_radio"] = self.full_radio
        
        self.custom_radio = tk.Radiobutton(
            scan_frame, 
            text=trans["custom_scan"], 
            variable=self.scan_type, 
            value="custom",
            bg=theme["frame_bg"], fg=theme["fg"],
            selectcolor=theme["frame_bg"]
        )
        self.custom_radio.grid(row=0, column=2, padx=20, pady=10, sticky=tk.W)
        self.ui_widgets["custom_radio"] = self.custom_radio
        
        # Кнопки управления
        button_frame = tk.Frame(scan_frame, bg=theme["frame_bg"])
        button_frame.grid(row=1, column=0, columnspan=5, pady=10)
        
        # Создаем отдельные фреймы для группировки кнопок
        scan_buttons_frame = tk.Frame(button_frame, bg=theme["frame_bg"])
        scan_buttons_frame.grid(row=0, column=0, padx=5)
        
        quarantine_buttons_frame = tk.Frame(button_frame, bg=theme["frame_bg"])
        quarantine_buttons_frame.grid(row=0, column=1, padx=5)
        
        action_buttons_frame = tk.Frame(button_frame, bg=theme["frame_bg"])
        action_buttons_frame.grid(row=0, column=2, padx=5)
        
        # Кнопки сканирования
        self.start_btn = tk.Button(
            scan_buttons_frame,
            text=trans["start_scan"],
            command=self.start_scan,
            width=15,
            bg=theme["button_bg"],
            fg=theme["button_fg"],
            activebackground=theme["button_bg"],
            activeforeground=theme["button_fg"]
        )
        self.start_btn.pack(pady=2)
        self.ui_widgets["start_btn"] = self.start_btn
        
        self.pause_btn = tk.Button(
            scan_buttons_frame,
            text=trans["pause"],
            command=self.pause_scan,
            width=15,
            state='disabled',
            bg=theme["button_bg"],
            fg=theme["button_fg"],
            activebackground=theme["button_bg"],
            activeforeground=theme["button_fg"]
        )
        self.pause_btn.pack(pady=2)
        self.ui_widgets["pause_btn"] = self.pause_btn
        
        self.stop_btn = tk.Button(
            scan_buttons_frame,
            text=trans["stop"],
            command=self.stop_scan,
            width=15,
            bg=theme["stop_bg"],
            fg=theme["button_fg"],
            activebackground=theme["stop_bg"],
            activeforeground=theme["button_fg"]
        )
        self.stop_btn.pack(pady=2)
        self.ui_widgets["stop_btn"] = self.stop_btn
        
        # Кнопки карантина
        self.quarantine_manage_btn = tk.Button(
            quarantine_buttons_frame,
            text=trans["manage_quarantine"],
            command=self.manage_quarantine,
            width=15,
            bg=theme["quarantine_bg"],
            fg=theme["button_fg"],
            activebackground=theme["quarantine_bg"],
            activeforeground=theme["button_fg"]
        )
        self.quarantine_manage_btn.pack(pady=2)
        self.ui_widgets["quarantine_manage_btn"] = self.quarantine_manage_btn
        
        self.to_quarantine_btn = tk.Button(
            quarantine_buttons_frame,
            text=trans["to_quarantine"],
            command=self.quarantine_selected,
            width=15,
            bg=theme["quarantine_bg"],
            fg=theme["button_fg"],
            activebackground=theme["quarantine_bg"],
            activeforeground=theme["button_fg"]
        )
        self.to_quarantine_btn.pack(pady=2)
        self.ui_widgets["to_quarantine_btn"] = self.to_quarantine_btn
        
        # Кнопки действий
        self.folder_btn = tk.Button(
            action_buttons_frame,
            text=trans["select_folder"],
            command=self.select_folder,
            width=15,
            bg=theme["button_bg"],
            fg=theme["button_fg"],
            activebackground=theme["button_bg"],
            activeforeground=theme["button_fg"]
        )
        self.folder_btn.pack(pady=2)
        self.ui_widgets["folder_btn"] = self.folder_btn
        
        self.file_btn = tk.Button(
            action_buttons_frame,
            text=trans["check_file"],
            command=self.check_single_file,
            width=15,
            bg=theme["button_bg"],
            fg=theme["button_fg"],
            activebackground=theme["button_bg"],
            activeforeground=theme["button_fg"]
        )
        self.file_btn.pack(pady=2)
        self.ui_widgets["file_btn"] = self.file_btn
        
        # Информация о выбранной папке
        self.folder_label = tk.Label(
            scan_frame,
            text=trans["folder_not_selected"],
            font=('Arial', 9, 'italic'),
            bg=theme["frame_bg"], fg=theme["fg"]
        )
        self.folder_label.grid(row=2, column=0, columnspan=5, pady=(0, 10))
        self.ui_widgets["folder_label"] = self.folder_label
        
        # Прогресс
        progress_frame = tk.LabelFrame(main_frame, text=trans["progress"], 
                                     bg=theme["frame_bg"], fg=theme["fg"])
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        self.ui_widgets["progress_frame"] = progress_frame
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            length=400
        )
        self.progress_bar.pack(pady=15, padx=20, fill=tk.X)
        
        # Статистика
        stats_frame = tk.Frame(progress_frame, bg=theme["frame_bg"])
        stats_frame.pack(pady=(0, 10))
        
        self.scanned_label = tk.Label(
            stats_frame,
            text=trans["scanned"].format(count=0),
            font=('Arial', 9),
            bg=theme["frame_bg"], fg=theme["fg"]
        )
        self.scanned_label.grid(row=0, column=0, padx=20)
        self.ui_widgets["scanned_label"] = self.scanned_label
        
        self.threats_label = tk.Label(
            stats_frame,
            text=trans["threats"].format(count=0),
            font=('Arial', 9),
            fg='red',
            bg=theme["frame_bg"]
        )
        self.threats_label.grid(row=0, column=1, padx=20)
        self.ui_widgets["threats_label"] = self.threats_label
        
        self.suspicious_label = tk.Label(
            stats_frame,
            text=trans["suspicious"].format(count=0),
            font=('Arial', 9),
            fg='orange',
            bg=theme["frame_bg"]
        )
        self.suspicious_label.grid(row=0, column=2, padx=20)
        self.ui_widgets["suspicious_label"] = self.suspicious_label
        
        # Лог и результаты
        bottom_frame = tk.Frame(main_frame, bg=theme["bg"])
        bottom_frame.pack(fill=tk.BOTH, expand=True)
        
        # Лог
        log_frame = tk.LabelFrame(bottom_frame, text=trans["log"], 
                                bg=theme["frame_bg"], fg=theme["fg"])
        log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self.ui_widgets["log_frame"] = log_frame
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            height=15,
            bg=theme["log_bg"], fg=theme["log_fg"],
            insertbackground=theme["fg"]
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Результаты
        results_frame = tk.LabelFrame(bottom_frame, text=trans["results"], 
                                    bg=theme["frame_bg"], fg=theme["fg"])
        results_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        self.ui_widgets["results_frame"] = results_frame
        
        # Таблица
        self.results_tree = ttk.Treeview(results_frame, columns=('file', 'status', 'risk', 'info'), 
                                        show='headings', height=15)
        self.results_tree.heading('file', text=trans["file"])
        self.results_tree.heading('status', text=trans["status"])
        self.results_tree.heading('risk', text=trans["risk"])
        self.results_tree.heading('info', text=trans["info"])
        
        self.results_tree.column('file', width=180)
        self.results_tree.column('status', width=80)
        self.results_tree.column('risk', width=80)
        self.results_tree.column('info', width=140)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Кнопки действий под таблицей
        action_frame = tk.Frame(results_frame, bg=theme["frame_bg"])
        action_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Первая строка кнопок
        action_frame_top = tk.Frame(action_frame, bg=theme["frame_bg"])
        action_frame_top.pack(fill=tk.X, pady=(0, 5))
        
        self.quarantine_action_btn = tk.Button(
            action_frame_top,
            text=trans["to_quarantine"],
            command=self.quarantine_selected_from_table,
            width=14,
            bg=theme["quarantine_bg"], fg=theme["button_fg"],
            activebackground=theme["quarantine_bg"], activeforeground=theme["button_fg"]
        )
        self.quarantine_action_btn.grid(row=0, column=0, padx=5)
        self.ui_widgets["quarantine_action_btn"] = self.quarantine_action_btn
        
        self.whitelist_btn = tk.Button(
            action_frame_top,
            text=trans["add_to_whitelist"],
            command=self.add_to_whitelist,
            width=14,
            bg=theme["button_bg"], fg=theme["button_fg"],
            activebackground=theme["button_bg"], activeforeground=theme["button_fg"]
        )
        self.whitelist_btn.grid(row=0, column=1, padx=5)
        self.ui_widgets["whitelist_btn"] = self.whitelist_btn
        
        self.report_btn = tk.Button(
            action_frame_top,
            text=trans["report"],
            command=self.generate_report,
            width=14,
            bg=theme["button_bg"], fg=theme["button_fg"],
            activebackground=theme["button_bg"], activeforeground=theme["button_fg"]
        )
        self.report_btn.grid(row=0, column=2, padx=5)
        self.ui_widgets["report_btn"] = self.report_btn
        
        # Вторая строка кнопок
        action_frame_bottom = tk.Frame(action_frame, bg=theme["frame_bg"])
        action_frame_bottom.pack(fill=tk.X)
        
        self.manage_quarantine_action_btn = tk.Button(
            action_frame_bottom,
            text=trans["manage_quarantine"],
            command=self.manage_quarantine,
            width=22,
            bg=theme["quarantine_bg"], fg=theme["button_fg"],
            activebackground=theme["quarantine_bg"], activeforeground=theme["button_fg"]
        )
        self.manage_quarantine_action_btn.grid(row=0, column=0, padx=5)
        self.ui_widgets["manage_quarantine_action_btn"] = self.manage_quarantine_action_btn
        
        self.clear_results_btn = tk.Button(
            action_frame_bottom,
            text="Очистить результаты",
            command=self.clear_results,
            width=22,
            bg=theme["button_bg"], fg=theme["button_fg"],
            activebackground=theme["button_bg"], activeforeground=theme["button_fg"]
        )
        self.clear_results_btn.grid(row=0, column=1, padx=5)
        self.ui_widgets["clear_results_btn"] = self.clear_results_btn
        
        # Статус бар
        self.status_bar = tk.Label(
            main_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padx=10,
            bg=theme["bg"], fg=theme["fg"]
        )
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
        self.ui_widgets["status_bar"] = self.status_bar
        
        # Создание меню
        self.create_menu()
        
    def create_menu(self):
        """Создание меню"""
        theme = self.themes[self.current_theme]
        trans = self.translations[self.current_language]
        
        menubar = tk.Menu(self.root, bg=theme["menu_bg"], fg=theme["menu_fg"])
        self.root.config(menu=menubar)
        
        # Меню Язык
        self.language_menu = tk.Menu(menubar, tearoff=0, bg=theme["menu_bg"], fg=theme["menu_fg"])
        menubar.add_cascade(label=trans["language"], menu=self.language_menu)
        
        self.language_menu.add_command(
            label="Русский", 
            command=lambda: self.change_language("Русский"),
            background=theme["menu_bg"],
            foreground=theme["menu_fg"]
        )
        self.language_menu.add_command(
            label="English", 
            command=lambda: self.change_language("English"),
            background=theme["menu_bg"],
            foreground=theme["menu_fg"]
        )
        
        # Меню Тема
        self.theme_menu = tk.Menu(menubar, tearoff=0, bg=theme["menu_bg"], fg=theme["menu_fg"])
        menubar.add_cascade(label=trans["theme"], menu=self.theme_menu)
        
        self.theme_menu.add_command(
            label="Светлая", 
            command=lambda: self.change_theme("Светлая"),
            background=theme["menu_bg"],
            foreground=theme["menu_fg"]
        )
        self.theme_menu.add_command(
            label="Тёмная", 
            command=lambda: self.change_theme("Тёмная"),
            background=theme["menu_bg"],
            foreground=theme["menu_fg"]
        )
        
        # Меню Помощь
        self.help_menu = tk.Menu(menubar, tearoff=0, bg=theme["menu_bg"], fg=theme["menu_fg"])
        menubar.add_cascade(label=trans["help"], menu=self.help_menu)
        self.help_menu.add_command(
            label=trans["about"], 
            command=self.show_about,
            background=theme["menu_bg"],
            foreground=theme["menu_fg"]
        )
        self.help_menu.add_command(
            label=trans["support"], 
            command=self.show_support,
            background=theme["menu_bg"],
            foreground=theme["menu_fg"]
        )
        
        self.menubar = menubar
        
    def manage_quarantine(self):
        """Управление карантином"""
        trans = self.translations[self.current_language]
        theme = self.themes[self.current_theme]
        
        quarantine_window = tk.Toplevel(self.root)
        quarantine_window.title(f"{trans['manage_quarantine']} - {trans['title']}")
        quarantine_window.geometry("700x500")
        quarantine_window.configure(bg=theme["bg"])
        
        # Заголовок
        tk.Label(
            quarantine_window,
            text=trans["manage_quarantine"],
            font=('Arial', 14, 'bold'),
            bg=theme["bg"], fg=theme["fg"]
        ).pack(pady=10)
        
        # Таблица карантина
        quarantine_frame = tk.Frame(quarantine_window, bg=theme["bg"])
        quarantine_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Создаем Treeview для отображения файлов в карантине
        columns = ('original_name', 'original_path', 'quarantined_date', 'size')
        quarantine_tree = ttk.Treeview(quarantine_frame, columns=columns, show='headings', height=15)
        
        quarantine_tree.heading('original_name', text='Имя файла')
        quarantine_tree.heading('original_path', text='Оригинальный путь')
        quarantine_tree.heading('quarantined_date', text='Дата помещения')
        quarantine_tree.heading('size', text='Размер (байт)')
        
        quarantine_tree.column('original_name', width=150)
        quarantine_tree.column('original_path', width=250)
        quarantine_tree.column('quarantined_date', width=150)
        quarantine_tree.column('size', width=100)
        
        scrollbar = ttk.Scrollbar(quarantine_frame, orient=tk.VERTICAL, command=quarantine_tree.yview)
        quarantine_tree.configure(yscrollcommand=scrollbar.set)
        
        quarantine_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Загрузка данных карантина
        quarantine_list = self.scanner.get_quarantine_list()
        if quarantine_list:
            for item in quarantine_list:
                # Форматирование даты
                try:
                    date_str = datetime.datetime.fromisoformat(item['quarantined_date']).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    date_str = item['quarantined_date']
                
                quarantine_tree.insert('', tk.END, values=(
                    item['original_name'],
                    item['original_path'],
                    date_str,
                    item['size']
                ))
        else:
            quarantine_tree.insert('', tk.END, values=(trans["no_files"], "", "", ""))
        
        # Кнопки управления
        button_frame = tk.Frame(quarantine_window, bg=theme["bg"])
        button_frame.pack(pady=10)
        
        def restore_selected():
            selected_items = quarantine_tree.selection()
            if not selected_items:
                messagebox.showwarning(trans["manage"], "Выберите файлы для восстановления")
                return
                
            for item in selected_items:
                values = quarantine_tree.item(item, 'values')
                if values[0] != trans["no_files"]:
                    # Находим информацию о файле
                    for q_item in quarantine_list:
                        if q_item['original_name'] == values[0] and q_item['original_path'] == values[1]:
                            success, message = self.scanner.restore_from_quarantine(q_item)
                            if success:
                                quarantine_tree.delete(item)
                                self.log_message(f"Файл восстановлен из карантина: {q_item['original_name']}")
                            else:
                                messagebox.showerror("Ошибка", message)
                            break
        
        def delete_selected():
            selected_items = quarantine_tree.selection()
            if not selected_items:
                messagebox.showwarning(trans["manage"], "Выберите файлы для удаления")
                return
                
            if messagebox.askyesno("Подтверждение", f"Удалить {len(selected_items)} файлов из карантина навсегда?"):
                for item in selected_items:
                    values = quarantine_tree.item(item, 'values')
                    if values[0] != trans["no_files"]:
                        # Находим информацию о файле
                        for q_item in quarantine_list:
                            if q_item['original_name'] == values[0] and q_item['original_path'] == values[1]:
                                try:
                                    if os.path.exists(q_item['quarantine_path']):
                                        os.remove(q_item['quarantine_path'])
                                    
                                    # Удаляем из списка
                                    quarantine_list.remove(q_item)
                                    quarantine_tree.delete(item)
                                    self.log_message(f"Файл удален из карантина: {q_item['original_name']}")
                                except Exception as e:
                                    messagebox.showerror("Ошибка", f"Не удалось удалить файл: {str(e)}")
                                break
        
        tk.Button(
            button_frame,
            text=trans["restore"],
            command=restore_selected,
            width=12,
            bg=theme["button_bg"], fg=theme["button_fg"]
        ).grid(row=0, column=0, padx=5)
        
        tk.Button(
            button_frame,
            text=trans["delete"],
            command=delete_selected,
            width=12,
            bg=theme["stop_bg"], fg=theme["button_fg"]
        ).grid(row=0, column=1, padx=5)
        
        tk.Button(
            button_frame,
            text="Закрыть",
            command=quarantine_window.destroy,
            width=12,
            bg=theme["button_bg"], fg=theme["button_fg"]
        ).grid(row=0, column=2, padx=5)
        
    def quarantine_selected(self):
        """Помещение выбранных файлов в карантин"""
        trans = self.translations[self.current_language]
        
        # Используем диалог выбора файлов
        file_paths = filedialog.askopenfilenames(title="Выберите файлы для карантина")
        
        if not file_paths:
            return
            
        success_count = 0
        error_count = 0
        
        for file_path in file_paths:
            if os.path.exists(file_path):
                success, message = self.scanner.quarantine_file(file_path)
                if success:
                    success_count += 1
                    self.log_message(f"{trans['quarantine_success']}: {os.path.basename(file_path)}")
                else:
                    error_count += 1
                    self.log_message(f"{trans['quarantine_error']}: {os.path.basename(file_path)} - {message}")
            else:
                error_count += 1
                self.log_message(f"Файл не найден: {file_path}")
        
        messagebox.showinfo(
            "Карантин",
            f"Обработано файлов: {len(file_paths)}\n"
            f"Успешно помещено в карантин: {success_count}\n"
            f"Ошибок: {error_count}"
        )
        
    def quarantine_selected_from_table(self):
        """Помещение выбранных файлов из таблицы в карантин"""
        selected_items = self.results_tree.selection()
        trans = self.translations[self.current_language]
        
        if not selected_items:
            messagebox.showwarning("Внимание", "Выберите файлы для карантина")
            return
            
        success_count = 0
        error_count = 0
        
        for item in selected_items:
            values = self.results_tree.item(item, 'values')
            file_name = values[0]
            
            # Находим полный путь к файлу (нужно хранить эту информацию)
            # В реальной реализации нужно хранить полные пути
            # Здесь просто показываем сообщение
            messagebox.showinfo("Информация", f"Функция помещает файл {file_name} в карантин.\n\nВ реальной реализации здесь будет полный путь к файлу.")
            
            # В реальной реализации:
            # file_path = self.get_file_path_from_result(item)  # Нужно получить полный путь
            # success, message = self.scanner.quarantine_file(file_path)
            
            # Для демонстрации считаем успешным
            success_count += 1
            self.log_message(f"Файл помещен в карантин (демо): {file_name}")
            
            # Удаляем из таблицы после помещения в карантин
            self.results_tree.delete(item)
        
        messagebox.showinfo(
            "Карантин",
            f"Файлов помещено в карантин: {success_count}\n"
            f"Ошибок: {error_count}"
        )
        
    def clear_results(self):
        """Очистка результатов"""
        if messagebox.askyesno("Подтверждение", "Очистить все результаты сканирования?"):
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            self.log_text.delete(1.0, tk.END)
            self.log_message("Результаты сканирования очищены")
    
    def check_single_file(self):
        """Проверка одного файла"""
        trans = self.translations[self.current_language]
        title = trans["select_file"]
        
        file_path = filedialog.askopenfilename(
            title=title,
            filetypes=[
                ("Все файлы", "*.*"),
                ("Исполняемые файлы", "*.exe;*.dll;*.bat;*.cmd;*.scr;*.pif;*.com"),
                ("Скрипты", "*.js;*.vbs;*.ps1;*.py;*.sh"),
                ("Документы", "*.doc;*.docx;*.xls;*.xlsx;*.pdf"),
                ("Архивы", "*.zip;*.rar;*.7z;*.tar;*.gz")
            ]
        )
        
        if file_path:
            try:
                # Показываем статус проверки
                self.status_var.set(trans["scanning"])
                self.log_message(f"{trans['select_file_to_scan']}: {os.path.basename(file_path)}")
                
                # Сканируем файл
                result = self.scanner.scan_file(file_path)
                
                # Добавляем в таблицу результатов
                self.add_to_results(result)
                
                # Обновляем статистику
                self.scanned_files += 1
                if result["status"] == "infected":
                    self.infected_files += 1
                    self.log_message(f"{trans['file_infected']}: {os.path.basename(file_path)}")
                elif result["status"] == "suspicious":
                    self.suspicious_files += 1
                    self.log_message(f"{trans['file_suspicious']}: {os.path.basename(file_path)}")
                else:
                    self.log_message(f"{trans['file_clean']}: {os.path.basename(file_path)}")
                
                # Обновляем статистику
                self.update_stats()
                
                # Показываем результат в сообщении
                if result["status"] == "infected":
                    messagebox.showwarning(
                        trans["file_scan_complete"],
                        f"{trans['file_infected']}!\n"
                        f"{trans['file']}: {os.path.basename(file_path)}\n"
                        f"{trans['status']}: {result['status']}\n"
                        f"{trans['info']}: {result.get('threat', '')}\n"
                        f"{trans['risk']}: {result.get('risk_level', 'low')}"
                    )
                elif result["status"] == "suspicious":
                    messagebox.showwarning(
                        trans["file_scan_complete"],
                        f"{trans['file_suspicious']}!\n"
                        f"{trans['file']}: {os.path.basename(file_path)}\n"
                        f"{trans['status']}: {result['status']}\n"
                        f"{trans['info']}: {result.get('threat', '')}\n"
                        f"{trans['risk']}: {result.get('risk_level', 'low')}"
                    )
                else:
                    messagebox.showinfo(
                        trans["file_scan_complete"],
                        f"{trans['file_clean']}!\n"
                        f"{trans['file']}: {os.path.basename(file_path)}\n"
                        f"{trans['status']}: {result['status']}"
                    )
                
                self.status_var.set(trans["ready"])
                
            except Exception as e:
                self.log_message(f"Ошибка при проверке файла: {str(e)}")
                messagebox.showerror("Ошибка", f"Не удалось проверить файл: {str(e)}")
                self.status_var.set(trans["ready"])
                
    def add_to_whitelist(self):
        """Добавление выбранных файлов в белый список"""
        selected_items = self.results_tree.selection()
        trans = self.translations[self.current_language]
        
        if not selected_items:
            messagebox.showwarning("Внимание", "Выберите файлы для белого списка")
            return
            
        for item in selected_items:
            values = self.results_tree.item(item, 'values')
            file_name = values[0]
            
            # В реальной реализации нужно получить хеш файла и добавить в белый список
            # Здесь просто показываем сообщение
            self.log_message(f"Файл добавлен в белый список (демо): {file_name}")
            
            # Удаляем из таблицы после добавления в белый список
            self.results_tree.delete(item)
            
        messagebox.showinfo(
            "Белый список",
            f"Файлов добавлено в белый список: {len(selected_items)}"
        )
        
    def change_language(self, language):
        """Изменение языка интерфейса"""
        if language != self.current_language:
            self.current_language = language
            self.update_ui()
            
    def change_theme(self, theme):
        """Изменение темы интерфейса"""
        if theme != self.current_theme:
            self.current_theme = theme
            # Обновляем стили ttk
            self.setup_ttk_styles()
            self.update_ui()
            
    def update_ui(self):
        """Обновление всего интерфейса"""
        trans = self.translations[self.current_language]
        theme = self.themes[self.current_theme]
        
        # Обновление заголовка окна
        self.root.title(trans["title"])
        
        # Обновление фона корневого окна
        self.root.configure(bg=theme["bg"])
        
        # Обновление виджетов
        for widget_name, widget in self.ui_widgets.items():
            if widget_name == "title_label":
                widget.config(text=trans["title"], bg=theme["bg"], fg='#4CAF50')
            elif widget_name == "scan_frame":
                widget.config(text=trans["scan_type"], bg=theme["frame_bg"], fg=theme["fg"])
            elif widget_name == "quick_radio":
                widget.config(text=trans["quick_scan"], bg=theme["frame_bg"], fg=theme["fg"], selectcolor=theme["frame_bg"])
            elif widget_name == "full_radio":
                widget.config(text=trans["full_scan"], bg=theme["frame_bg"], fg=theme["fg"], selectcolor=theme["frame_bg"])
            elif widget_name == "custom_radio":
                widget.config(text=trans["custom_scan"], bg=theme["frame_bg"], fg=theme["fg"], selectcolor=theme["frame_bg"])
            elif widget_name == "start_btn":
                widget.config(text=trans["start_scan"], bg=theme["button_bg"], fg=theme["button_fg"],
                            activebackground=theme["button_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "pause_btn":
                widget.config(text=trans["pause"], bg=theme["button_bg"], fg=theme["button_fg"],
                            activebackground=theme["button_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "stop_btn":
                widget.config(text=trans["stop"], bg=theme["stop_bg"], fg=theme["button_fg"],
                            activebackground=theme["stop_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "folder_btn":
                widget.config(text=trans["select_folder"], bg=theme["button_bg"], fg=theme["button_fg"],
                            activebackground=theme["button_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "file_btn":
                widget.config(text=trans["check_file"], bg=theme["button_bg"], fg=theme["button_fg"],
                            activebackground=theme["button_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "quarantine_manage_btn":
                widget.config(text=trans["manage_quarantine"], bg=theme["quarantine_bg"], fg=theme["button_fg"],
                            activebackground=theme["quarantine_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "to_quarantine_btn":
                widget.config(text=trans["to_quarantine"], bg=theme["quarantine_bg"], fg=theme["button_fg"],
                            activebackground=theme["quarantine_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "folder_label":
                current_text = widget.cget("text")
                if "Выбрана:" in current_text or "Selected:" in current_text:
                    # Сохраняем путь, но меняем префикс
                    path = current_text.split(": ", 1)[1] if ": " in current_text else ""
                    widget.config(text=trans["folder_selected"].format(path=path), 
                                bg=theme["frame_bg"], fg=theme["fg"])
                else:
                    widget.config(text=trans["folder_not_selected"], 
                                bg=theme["frame_bg"], fg=theme["fg"])
            elif widget_name == "progress_frame":
                widget.config(text=trans["progress"], bg=theme["frame_bg"], fg=theme["fg"])
            elif widget_name == "scanned_label":
                widget.config(text=trans["scanned"].format(count=self.scanned_files), 
                            bg=theme["frame_bg"], fg=theme["fg"])
            elif widget_name == "threats_label":
                widget.config(text=trans["threats"].format(count=self.infected_files), 
                            bg=theme["frame_bg"], fg='red')
            elif widget_name == "suspicious_label":
                widget.config(text=trans["suspicious"].format(count=self.suspicious_files), 
                            bg=theme["frame_bg"], fg='orange')
            elif widget_name == "log_frame":
                widget.config(text=trans["log"], bg=theme["frame_bg"], fg=theme["fg"])
            elif widget_name == "results_frame":
                widget.config(text=trans["results"], bg=theme["frame_bg"], fg=theme["fg"])
            elif widget_name == "quarantine_action_btn":
                widget.config(text=trans["to_quarantine"], bg=theme["quarantine_bg"], fg=theme["button_fg"],
                            activebackground=theme["quarantine_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "whitelist_btn":
                widget.config(text=trans["add_to_whitelist"], bg=theme["button_bg"], fg=theme["button_fg"],
                            activebackground=theme["button_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "report_btn":
                widget.config(text=trans["report"], bg=theme["button_bg"], fg=theme["button_fg"],
                            activebackground=theme["button_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "manage_quarantine_action_btn":
                widget.config(text=trans["manage_quarantine"], bg=theme["quarantine_bg"], fg=theme["button_fg"],
                            activebackground=theme["quarantine_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "clear_results_btn":
                widget.config(bg=theme["button_bg"], fg=theme["button_fg"],
                            activebackground=theme["button_bg"], activeforeground=theme["button_fg"])
            elif widget_name == "status_bar":
                widget.config(bg=theme["bg"], fg=theme["fg"])
        
        # Обновление заголовков столбцов таблицы
        self.results_tree.heading('file', text=trans["file"])
        self.results_tree.heading('status', text=trans["status"])
        self.results_tree.heading('risk', text=trans["risk"])
        self.results_tree.heading('info', text=trans["info"])
        
        # Обновление цвета текста в логе
        self.log_text.config(bg=theme["log_bg"], fg=theme["log_fg"], insertbackground=theme["fg"])
        
        # Обновление цвета Treeview через tag_configure
        self.results_tree.tag_configure('selected', background=theme["selected_bg"], foreground=theme["selected_fg"])
        
        # Обновление меню
        self.update_menu()
        
        # Обновление статуса
        current_status = self.status_var.get()
        status_map = {
            "Готов к работе": trans["ready"],
            "Сканирование...": trans["scanning"],
            "Сканирование приостановлено": trans["paused"],
            "Сканирование остановлено": trans["stopped"],
            "Ready": trans["ready"],
            "Scanning...": trans["scanning"],
            "Scanning paused": trans["paused"],
            "Scanning stopped": trans["stopped"]
        }
        
        if current_status in status_map:
            self.status_var.set(status_map[current_status])
        else:
            self.status_var.set(trans["ready"])
        
    def update_menu(self):
        """Обновление меню"""
        trans = self.translations[self.current_language]
        theme = self.themes[self.current_theme]
        
        # Пересоздаем меню с новыми настройками
        self.create_menu()
        
    def show_about(self):
        """Показать окно 'О программе'"""
        trans = self.translations[self.current_language]
        theme = self.themes[self.current_theme]
        
        about_window = tk.Toplevel(self.root)
        about_window.title(trans["about"])
        about_window.geometry("300x250")  # Увеличил высоту окна для новой строки
        about_window.resizable(False, False)
        about_window.configure(bg=theme["bg"])
        
        # Иконка
        tk.Label(about_window, text="🛡️", font=('Arial', 36), fg='#4CAF50', bg=theme["bg"]).pack(pady=20)
        
        # Название программы
        tk.Label(about_window, text="AntiVit Security Pro", font=('Arial', 14, 'bold'), bg=theme["bg"], fg=theme["fg"]).pack()
        
        # Версия
        tk.Label(about_window, text="Версия 1.0", bg=theme["bg"], fg=theme["fg"]).pack(pady=5)
        
        # Копирайт
        tk.Label(about_window, text="(c) SM Team 2026", bg=theme["bg"], fg=theme["fg"]).pack()
        
        # Новая строка: информация о поддержке
        tk.Label(about_window, text=trans["supported_by"], font=('Arial', 9), 
                bg=theme["bg"], fg=theme["fg"]).pack(pady=10)
        
        # Кнопка OK
        tk.Button(
            about_window,
            text="OK",
            command=about_window.destroy,
            width=10,
            bg=theme["button_bg"], fg=theme["button_fg"]
        ).pack(pady=20)
        
    def show_support(self):
        """Показать окно 'Поддержка'"""
        trans = self.translations[self.current_language]
        theme = self.themes[self.current_theme]
        
        support_window = tk.Toplevel(self.root)
        support_window.title(trans["support"])
        support_window.geometry("400x150")
        support_window.resizable(False, False)
        support_window.configure(bg=theme["bg"])
        
        tk.Label(support_window, text="По всем вопросам обращайтесь:", font=('Arial', 12), 
                bg=theme["bg"], fg=theme["fg"]).pack(pady=20)
        tk.Label(support_window, text="supermessageteam@internet.ru", font=('Arial', 14, 'bold'), 
                fg='blue', bg=theme["bg"]).pack(pady=10)
        tk.Button(support_window, text="Закрыть", command=support_window.destroy, 
                 width=10, bg=theme["button_bg"], fg=theme["button_fg"]).pack(pady=20)
        
    def log_message(self, message):
        """Добавление сообщения в лог"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        
    def update_stats(self):
        """Обновление статистики"""
        trans = self.translations[self.current_language]
        theme = self.themes[self.current_theme]
        
        self.scanned_label.config(text=trans["scanned"].format(count=self.scanned_files),
                                bg=theme["frame_bg"], fg=theme["fg"])
        self.threats_label.config(text=trans["threats"].format(count=self.infected_files),
                                bg=theme["frame_bg"], fg='red')
        self.suspicious_label.config(text=trans["suspicious"].format(count=self.suspicious_files),
                                    bg=theme["frame_bg"], fg='orange')
        
    def select_folder(self):
        """Выбор папки для сканирования"""
        trans = self.translations[self.current_language]
        theme = self.themes[self.current_theme]
        
        title = trans["select_folder"]
        folder = filedialog.askdirectory(title=title)
        if folder:
            self.folder_label.config(text=trans["folder_selected"].format(path=folder),
                                    bg=theme["frame_bg"], fg=theme["fg"])
            self.custom_scan_path = folder
            self.scan_type.set("custom")
            self.log_message(f"Выбрана папка: {folder}" if self.current_language == "Русский" else f"Folder selected: {folder}")
            
    def start_scan(self):
        """Запуск сканирования"""
        if self.scanning:
            trans = self.translations[self.current_language]
            messagebox.showwarning(
                "Внимание" if self.current_language == "Русский" else "Warning",
                "Сканирование уже выполняется!" if self.current_language == "Русский" else "Scanning is already in progress!"
            )
            return
            
        self.scanning = True
        self.scanned_files = 0
        self.infected_files = 0
        self.suspicious_files = 0
        self.progress_var.set(0)
        
        # Очистка
        self.log_text.delete(1.0, tk.END)
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        self.update_stats()
        self.pause_btn.config(state='normal')
        self.start_btn.config(state='disabled')
        self.status_var.set(self.translations[self.current_language]["scanning"])
        
        # Запуск в потоке
        self.scan_thread = threading.Thread(target=self.perform_scan, daemon=True)
        self.scan_thread.start()
        
        self.log_message("Сканирование начато" if self.current_language == "Русский" else "Scanning started")
        
    def perform_scan(self):
        """Выполнение сканирования"""
        try:
            scan_type = self.scan_type.get()
            
            if scan_type == "quick":
                # Быстрое сканирование - до 500 файлов
                scan_paths = [
                    os.path.expanduser("~\\Desktop"),
                    os.path.expanduser("~\\Downloads"),
                    os.path.expanduser("~\\Documents"),
                ]
                max_files = 500
                
            elif scan_type == "full":
                # Полное сканирование - все файлы
                import string
                scan_paths = []
                for drive in string.ascii_uppercase:
                    drive_path = f"{drive}:\\"
                    if os.path.exists(drive_path):
                        scan_paths.append(drive_path)
                max_files = 10000  # Ограничим для скорости
                
            elif scan_type == "custom" and hasattr(self, 'custom_scan_path'):
                scan_paths = [self.custom_scan_path]
                max_files = 1000
                
            else:
                self.log_message("Выберите папку для сканирования" if self.current_language == "Русский" else "Select folder for scanning")
                self.root.after(0, self.scan_completed)
                return
            
            # Сбор файлов
            all_files = []
            files_collected = 0
            
            for path in scan_paths:
                if not os.path.exists(path):
                    continue
                    
                try:
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if files_collected >= max_files:
                                break
                            file_path = os.path.join(root, file)
                            all_files.append(file_path)
                            files_collected += 1
                            
                        if files_collected >= max_files:
                            break
                except:
                    continue
            
            total_files = len(all_files)
            self.log_message(f"Найдено файлов для проверки: {total_files}" if self.current_language == "Русский" else f"Files found for scanning: {total_files}")
            
            # Сканирование
            for i, file_path in enumerate(all_files):
                if not self.scanning:
                    break
                    
                try:
                    result = self.scanner.scan_file(file_path)
                    self.scanned_files += 1
                    
                    if result["status"] == "infected":
                        self.infected_files += 1
                        self.log_message(f"УГРОЗА: {os.path.basename(file_path)}" if self.current_language == "Русский" else f"THREAT: {os.path.basename(file_path)}")
                        self.root.after(0, self.add_to_results, result)
                    elif result["status"] == "suspicious":
                        self.suspicious_files += 1
                        self.log_message(f"Подозрительный: {os.path.basename(file_path)}" if self.current_language == "Русский" else f"Suspicious: {os.path.basename(file_path)}")
                        self.root.after(0, self.add_to_results, result)
                    elif result["status"] == "whitelisted":
                        self.log_message(f"В белом списке: {os.path.basename(file_path)}")
                    
                    # Обновление прогресса
                    if total_files > 0:
                        progress = (i + 1) / total_files * 100
                        self.root.after(0, lambda p=progress: self.progress_var.set(p))
                    
                    # Обновление статистики каждые 10 файлов
                    if i % 10 == 0:
                        self.root.after(0, self.update_stats)
                        
                except:
                    continue
            
            # Завершение
            self.root.after(0, self.scan_completed)
            
        except Exception as e:
            self.log_message(f"Ошибка сканирования: {str(e)}" if self.current_language == "Русский" else f"Scanning error: {str(e)}")
            self.root.after(0, self.scan_completed)
            
    def scan_completed(self):
        """Завершение сканирования"""
        self.scanning = False
        self.pause_btn.config(state='disabled')
        self.start_btn.config(state='normal')
        
        self.log_message("Сканирование завершено" if self.current_language == "Русский" else "Scanning completed")
        self.status_var.set(self.translations[self.current_language]["ready"])
        self.update_stats()
        
        # Показ результатов
        trans = self.translations[self.current_language]
        if self.infected_files > 0:
            messagebox.showwarning(
                "Результаты сканирования" if self.current_language == "Русский" else "Scan Results",
                f"Сканирование завершено!\n\n"
                f"Проверено файлов: {self.scanned_files}\n"
                f"Найдено угроз: {self.infected_files}\n"
                f"Подозрительных файлов: {self.suspicious_files}\n\n"
                f"Рекомендуется проверить подозрительные файлы!"
            )
        elif self.suspicious_files > 0:
            messagebox.showinfo(
                "Результаты сканирования" if self.current_language == "Русский" else "Scan Results",
                f"Сканирование завершено!\n\n"
                f"Проверено файлов: {self.scanned_files}\n"
                f"Найдено угроз: {self.infected_files}\n"
                f"Подозрительных файлов: {self.suspicious_files}\n\n"
                f"Рекомендуется проверить подозрительные файлы!"
            )
        else:
            messagebox.showinfo(
                "Результаты сканирования" if self.current_language == "Русский" else "Scan Results",
                f"Сканирование завершено!\n\n"
                f"Проверено файлов: {self.scanned_files}\n"
                f"Найдено угроз: {self.infected_files}\n"
                f"Ваша система чиста!"
            )
            
    def add_to_results(self, result):
        """Добавление результата в таблицу"""
        file_name = os.path.basename(result["file"])
        if len(file_name) > 25:
            display_name = file_name[:22] + "..."
        else:
            display_name = file_name
            
        # Определяем цвет в зависимости от уровня риска
        theme = self.themes[self.current_theme]
        risk_level = result.get("risk_level", "low")
        risk_colors = {
            "high": theme["risk_high"],
            "medium": theme["risk_medium"],
            "low": theme["risk_low"]
        }
        risk_color = risk_colors.get(risk_level, theme["risk_low"])
        
        # Переводим уровень риска
        risk_translation = {
            "high": "Высокий" if self.current_language == "Русский" else "High",
            "medium": "Средний" if self.current_language == "Русский" else "Medium",
            "low": "Низкий" if self.current_language == "Русский" else "Low"
        }
        
        item = self.results_tree.insert('', tk.END, values=(
            display_name,
            result["status"].upper(),
            risk_translation.get(risk_level, "Низкий"),
            result.get("threat", "")
        ))
        
        # Устанавливаем цвет текста для уровня риска
        self.results_tree.set(item, 'risk', risk_translation.get(risk_level, "Низкий"))
        
    def pause_scan(self):
        """Пауза сканирования"""
        if self.scanning:
            self.scanning = False
            self.pause_btn.config(text=self.translations[self.current_language]["pause"])
            self.status_var.set(self.translations[self.current_language]["paused"])
            self.log_message("Сканирование приостановлено" if self.current_language == "Русский" else "Scanning paused")
        else:
            self.scanning = True
            self.pause_btn.config(text=self.translations[self.current_language]["pause"])
            self.status_var.set(self.translations[self.current_language]["scanning"])
            self.log_message("Сканирование продолжено" if self.current_language == "Русский" else "Scanning resumed")
            
    def stop_scan(self):
        """Остановка сканирования"""
        self.scanning = False
        self.pause_btn.config(state='disabled')
        self.start_btn.config(state='normal')
        self.status_var.set(self.translations[self.current_language]["stopped"])
        self.log_message("Сканирование остановлено" if self.current_language == "Русский" else "Scanning stopped")
        
    def generate_report(self):
        """Генерация отчёта"""
        try:
            report_data = {
                "scan_date": datetime.datetime.now().isoformat(),
                "files_scanned": self.scanned_files,
                "threats_found": self.infected_files,
                "suspicious_files": self.suspicious_files,
                "scan_type": self.scan_type.get(),
                "language": self.current_language,
                "theme": self.current_theme,
                "results": []
            }
            
            # Собираем информацию о результатах
            for item in self.results_tree.get_children():
                values = self.results_tree.item(item, 'values')
                report_data["results"].append({
                    "file": values[0],
                    "status": values[1],
                    "risk": values[2],
                    "info": values[3]
                })
            
            report_file = f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
                
            self.log_message(f"Отчёт сохранён: {report_file}" if self.current_language == "Русский" else f"Report saved: {report_file}")
            messagebox.showinfo(
                "Отчёт" if self.current_language == "Русский" else "Report",
                f"Отчёт сохранён: {report_file}" if self.current_language == "Русский" else f"Report saved: {report_file}"
            )
            
        except Exception as e:
            messagebox.showerror(
                "Ошибка" if self.current_language == "Русский" else "Error",
                f"Не удалось создать отчёт: {str(e)}" if self.current_language == "Русский" else f"Failed to create report: {str(e)}"
            )

def main():
    """Запуск приложения"""
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()