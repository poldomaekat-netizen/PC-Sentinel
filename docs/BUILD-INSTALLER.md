# Сборка установщика Windows

Требуются Windows x64, **PowerShell 7**, SDK **.NET 10.0.402** из global.json и Inno Setup 6.3+ (сборка выпуска использует 6.7.3). Установите .NET SDK из официального источника Microsoft перед запуском команд.

Откройте PowerShell 7 в корне исходников:

    ./scripts/fetch-deps.ps1 -InstallInno
    ./scripts/build-installer.ps1
    ./scripts/package-source.ps1

fetch-deps загружает официальные установщики PawnIO 2.2.0 и, по флагу -InstallInno, Inno Setup 6.7.3. Проверяет закреплённые SHA256 и Authenticode. Сам PawnIO на компьютер сборки этот скрипт не устанавливает. Inno Setup устанавливается в вынесенный каталог инструментов текущего пользователя. [Условия Inno Setup](https://github.com/jrsoftware/issrc/blob/is-6_7_3/license.txt).

## Каталоги и результат

SDK, NuGet-кеш, результаты тестов и временные публикации хранятся вне исходников. По умолчанию используется соседний каталог PCSentinel-Build; в CI — RUNNER_TEMP/PCSentinel-Build. Другое место задаётся параметром -BuildRoot или переменной PC_SENTINEL_BUILD_ROOT. BuildRoot должен находиться вне исходного проекта.

Результаты в installer/Output/:

- PCSentinel-0.3.2-Setup.exe и его .sha256;
- BUILD-MANIFEST.json;
- PCSentinel-0.3.2-Source.zip и его .sha256.

Копия Setup также помещается в корень проекта. Версия приложения: 0.3.2, версия файла: 0.3.2.1. Релиз содержит установщик; portable не распространяется.

Folder-публикация находится в BuildRoot/publish/v0.3.2-Folder. UI включает Windows Desktop runtime; Service/ содержит независимую службу с .NET Core runtime без WPF. Для обоих PublishSingleFile=false, IncludeNativeLibrariesForSelfExtract=false. В Setup не включаются SDK, NuGet-кеш, тестовые БД, скриншоты, отчёты тестов или bin/obj исходного проекта.

NuGet restore выполняется с --locked-mode. Скрипт запускает тесты, затем публикует приложение/службу и компилирует Setup. CI в .github/workflows/build-windows.yml выполняет эти же этапы и сохраняет установщик, исходники и результаты тестов как артефакты.

## Подпись

Текущий выпуск не подписан Authenticode. Поддержка подписи предусмотрена; при появлении действительного сертификата с Code Signing EKU и закрытым ключом в CurrentUser/My:

    ./scripts/build-installer.ps1 -CertificateThumbprint ОТКРЫТЫЙ_ОТПЕЧАТОК

Скрипт подписывает собственные EXE/DLL, установщик и деинсталлятор. Сертификаты и закрытые ключи не добавляйте в репозиторий. Самоподписанный корневой сертификат в доверенные хранилища не устанавливается.

## Проверка выпуска

Проверяются установка, обновление и удаление; запуск UI обычным пользователем; состояние службы и доступность температур; запрет пользовательской записи в установленную папку и канал службы; сохранение истории, настроек и PawnIO при удалении. Доступность датчиков на конкретном оборудовании проверяется отдельно. Сведения о существующих проверках: [TESTING.md](TESTING.md).
