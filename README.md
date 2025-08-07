[Русский README](#russian-readme)

# IDA Pro Anti-VM/Debug Scanner

A lightweight and useful IDA Pro plugin that helps detect anti-debugging and anti-virtualization techniques in the analyzed binary.

## Compatibility

Presumably, IDA Pro 9.0 and above. Apologies for potential compatibility issues with older versions.

## Installation

To install, follow these steps:

1.  Download the `anti_vm_scanner.py` file.
2.  Copy it to your IDA Pro plugins directory. This is usually:
    `C:\Program Files\IDA Professional <YOUR_VERSION>\plugins`
3.  Restart IDA Pro for it to re-scan the plugin list and load the new plugin.

## Usage

You can run the scan using one of the following methods:

*   Press `CTRL+ALT+A`.
*   Select the plugin via the IDA Pro menu: `Edit -> Plugins -> Anti-VM/Debug Scanner`.

## Examples

The scan and its results will be displayed in IDA Pro's Output Window, similar to the following:

```console
-----------------------------------------------------------------------------------------
[Anti-VM/Debug Scanner] Plugin initialized. Press Ctrl-Alt-A to run.
==================================================
[Anti-VM/Debug Scanner] Starting comprehensive scan...
==================================================
[-] Clearing previous highlights...
[-] Searching for suspicious mnemonics in code sections...
[+] Found 0 suspicious mnemonics.
[-] Searching for special instruction patterns in code sections...
[+] Found: Anti-VM: VMware backdoor, magic value 'VMXh' at 0x100061C7
[+] Found: Anti-VM: VMware backdoor, port number at 0x100061D6
[+] Found: Anti-VM: VMware backdoor, I/O port access at 0x100061DB
[+] Found 1 special instruction patterns.
[-] Searching for suspicious string artifacts...
[+] Found 0 suspicious strings.
[-] Searching for suspicious MAC address prefixes in data segments...
[*] Scanning segment '.rdata'...
[*] Scanning segment '.data'...
[+] Found 0 potential MAC address artifacts.
[-] Searching for Anti-Debugging API calls...
[+] Found: Anti-Debug: Call to OutputDebugStringA at 0x1000368B
[+] Found: Anti-Debug: Call to GetTickCount at 0x100018DA
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000195C
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000357E
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000422E
[+] Found: Anti-Debug: Call to GetTickCount at 0x10004D46
[+] Found: Anti-Debug: Call to GetTickCount at 0x10004DEF
[+] Found: Anti-Debug: Call to GetTickCount at 0x10006F5D
[+] Found: Anti-Debug: Call to GetTickCount at 0x100080B0
[+] Found: Anti-Debug: Call to GetTickCount at 0x100085F1
[+] Found: Anti-Debug: Call to GetTickCount at 0x100099AC
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000A394
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000AD85
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000AF21
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000B770
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000C2CD
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000FF6E
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000FFC8
[+] Found: Anti-Debug: Call to GetTickCount at 0x100106E4
[+] Found: Anti-Debug: Call to GetTickCount at 0x100107A8
[+] Found 20 potential Anti-Debugging API calls.

==================================================
[Anti-VM/Debug Scanner] Scan finished.
==================================================
[Anti-VM/Debug Scanner] Plugin terminated.
```

### Visual Highlighting and Comments

After the scan is complete, the script will automatically:

*   **Add comments** to the detected instructions (your existing comments will not be overwritten).
*   **Highlight** suspicious code sections in **bright red** for better visibility.

Here's what it looks like in IDA Pro:

![Example of suspicious code highlighting](IAVS_screenshots/Pasted%20image%2020250807182412.png)

### Example of Suspicious Mnemonic Detection

The plugin can also detect specific mnemonics that are often used in anti-debugging techniques:

```console
...
[-] Searching for suspicious mnemonics...
[+] Found: Anti-VM/Debug: SLDT at 0x401121
[+] Found: Anti-VM/Debug: SIDT at 0x4011B5
[+] Found: Anti-VM/Debug: STR at 0x401204
[+] Found 3 suspicious mnemonics.
...
```

Their visualization in IDA Pro:

![Example of suspicious mnemonic detection](IAVS_screenshots/Pasted%20image%2020250807182535.png)

---

<a name="russian-readme"></a>

# IDA Pro Anti-VM/Debug Scanner

Легкий и полезный плагин для IDA Pro, который помогает обнаружить анти-отладочные и анти-виртуализационные техники в анализируемом бинарном файле.

## Совместимость

Предположительно, IDA Pro 9.0 и выше. Извиняюсь за возможные проблемы совместимости с более старыми версиями.

## Установка

Для установки выполните следующие шаги:

1.  Загрузите файл `anti_vm_scanner.py`.
2.  Скопируйте его в директорию плагинов IDA Pro. Обычно это:
    `C:\Program Files\IDA Professional <ВАША_ВЕРСИЯ>\plugins`
3.  Перезапустите IDA Pro, чтобы она могла заново проверить список плагинов и загрузить новый.

## Использование

Запустить сканирование можно одним из следующих способов:

*   Нажмите сочетание клавиш `CTRL+ALT+A`.
*   Выберите плагин через меню IDA Pro: `Edit -> Plugins -> Anti-VM/Debug Scanner`.

## Примеры работы

Сканирование и его результаты будут выведены в Output Window IDA Pro, примерно так:

```console
-----------------------------------------------------------------------------------------
[Anti-VM/Debug Scanner] Plugin initialized. Press Ctrl-Alt-A to run.
==================================================
[Anti-VM/Debug Scanner] Starting comprehensive scan...
==================================================
[-] Clearing previous highlights...
[-] Searching for suspicious mnemonics in code sections...
[+] Found 0 suspicious mnemonics.
[-] Searching for special instruction patterns in code sections...
[+] Found: Anti-VM: VMware backdoor, magic value 'VMXh' at 0x100061C7
[+] Found: Anti-VM: VMware backdoor, port number at 0x100061D6
[+] Found: Anti-VM: VMware backdoor, I/O port access at 0x100061DB
[+] Found 1 special instruction patterns.
[-] Searching for suspicious string artifacts...
[+] Found 0 suspicious strings.
[-] Searching for suspicious MAC address prefixes in data segments...
[*] Scanning segment '.rdata'...
[*] Scanning segment '.data'...
[+] Found 0 potential MAC address artifacts.
[-] Searching for Anti-Debugging API calls...
[+] Found: Anti-Debug: Call to OutputDebugStringA at 0x1000368B
[+] Found: Anti-Debug: Call to GetTickCount at 0x100018DA
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000195C
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000357E
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000422E
[+] Found: Anti-Debug: Call to GetTickCount at 0x10004D46
[+] Found: Anti-Debug: Call to GetTickCount at 0x10004DEF
[+] Found: Anti-Debug: Call to GetTickCount at 0x10006F5D
[+] Found: Anti-Debug: Call to GetTickCount at 0x100080B0
[+] Found: Anti-Debug: Call to GetTickCount at 0x100085F1
[+] Found: Anti-Debug: Call to GetTickCount at 0x100099AC
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000A394
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000AD85
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000AF21
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000B770
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000C2CD
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000FF6E
[+] Found: Anti-Debug: Call to GetTickCount at 0x1000FFC8
[+] Found: Anti-Debug: Call to GetTickCount at 0x100106E4
[+] Found: Anti-Debug: Call to GetTickCount at 0x100107A8
[+] Found 20 potential Anti-Debugging API calls.

==================================================
[Anti-VM/Debug Scanner] Scan finished.
==================================================
[Anti-VM/Debug Scanner] Plugin terminated.
```

### Визуальное выделение и комментарии

После завершения сканирования, скрипт автоматически:

*   **Добавит комментарии** к обнаруженным инструкциям (ваши существующие комментарии при этом не будут перезаписаны).
*   **Подсветит** подозрительные участки кода **ярко-красным цветом** для лучшей видимости.

Вот как это выглядит в IDA Pro:

![Пример подсветки подозрительного кода](IAVS_screenshots/Pasted%20image%2020250807182412.png)

### Пример обнаружения подозрительных мнемоник

Плагин также способен обнаруживать специфичные мнемоники, которые часто используются в анти-отладочных техниках:

```console
...
[-] Searching for suspicious mnemonics...
[+] Found: Anti-VM/Debug: SLDT at 0x401121
[+] Found: Anti-VM/Debug: SIDT at 0x4011B5
[+] Found: Anti-VM/Debug: STR at 0x401204
[+] Found 3 suspicious mnemonics.
...
```

Их визуализация в IDA Pro:

![Пример обнаружения подозрительных мнемоник](IAVS_screenshots/Pasted%20image%2020250807182535.png)
