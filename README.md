# VT API Script

Скрипт обращается к VirusTotal API, получает JSON-отчёт по SHA-256.

## Запуск
1. `pip install requests`
2. `export VT_API_KEY="..."`
3. `python vt_api.py --sha256 <hash>`

## Mock
`python vt_api.py --mock`
