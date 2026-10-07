package i18n

func init() {
	for k, v := range appsEN {
		en[k] = v
	}
}

// Подтверждения при добавлении и переносе собственных приложений и названия правил ASR (выводятся через переменную).
var appsEN = map[string]string{
	"ВНИМАНИЕ: каталог данных внутри OneDrive: он синхронизируется в облако в открытом виде, пока приложение работает.\n":                                                    "WARNING: the data folder is inside OneDrive: it syncs to the cloud in plain form while the app runs.\n",
	"Приложение лежит там, где его может заменить обычная учётка: его копия будет помещена в каталог SessionVault (после обновления приложения: sessionvault refresh %s).\n": "The app lives where a regular account can replace it: its copy will be placed in the SessionVault folder (after the app updates: sessionvault refresh %s).\n",
	"Оно будет запускаться под собственной учёткой sv-<имя> с доступом к своим расшифрованным данным.\n":                                                                     "It will run under its own account sv-<name> with access to its own decrypted data.\n",
	"НЕ ПОДПИСАНО": "NOT SIGNED",
	"Приложение %s из файла экспорта.\nИсполняемый файл на этом ПК: %s\nИздатель (подпись): %s\nДанные: профиль основной учётки\\%s\nАргументы запуска из файла: %s\n": "App %s from the export file.\nExecutable on this PC: %s\nPublisher (signature): %s\nData: main account profile\\%s\nLaunch arguments from the file: %s\n",
	"Приложение: %s\nИздатель (подпись): %s\nДанные: %s -> защищённая рабочая папка\nАргументы: %s\n":                                                                  "App: %s\nPublisher (signature): %s\nData: %s -> protected working folder\nArguments: %s\n",

	"Steam уже запущен вне SessionVault: закройте его и повторите":                                                                        "Steam is already running outside SessionVault: close it and try again",
	"закройте Steam (в том числе из трея) и повторите":                                                                                    "close Steam (including in the tray) and try again",
	"Steam не переносится экспортом: путь клиента на новом ПК другой, защитите Steam там заново (sessionvault protect steam)":             "Steam is not moved by export: the client path differs on a new PC, protect Steam there again (sessionvault protect steam)",
	"Steam остаётся в вашей учётке: файлы входа зашифрованы, пока он закрыт, а на их местах приманка. Пока Steam запущен, файлы открыты.": "Steam stays in your account: the sign-in files are encrypted while it is closed and a decoy lies in their place. While Steam is running, the files are open.",
	"данные Steam больше 256 МБ: шифрование отменено":                                                                                     "Steam data is larger than 256 MB: encryption cancelled",
	"обфусцированные скрипты":                    "obfuscated scripts",
	"JS/VBS запускает скачанный exe":             "JS/VBS launches a downloaded exe",
	"исполняемое содержимое из почты и вебпочты": "executable content from email and webmail",
	"кража учётных данных из LSASS":              "credential theft from LSASS",
}
