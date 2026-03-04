#!/usr/bin/env python3
import os
import json
import requests

def get_file_report(sha256: str) -> dict:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise RuntimeError("Не задана переменная окружения VT_API_KEY")

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()

def print_summary(report: dict) -> None:
    attrs = report.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    print("=== Краткая сводка ===")
    print("SHA256:", report.get("data", {}).get("id", "N/A"))
    print("Тип:", attrs.get("type_description", "N/A"))
    print("Имя файла:", attrs.get("meaningful_name", "N/A"))
    print("Дата последнего анализа (unix):", attrs.get("last_analysis_date", "N/A"))

    print("\n=== Статистика детектов ===")
    # Обычно: malicious, suspicious, harmless, undetected, timeout, confirmed-timeout, failure, type-unsupported
    for k, v in stats.items():
        print(f"{k}: {v}")

    print("\n=== Движки, где есть срабатывания (malicious/suspicious) ===")
    found = False
    for engine, result in results.items():
        category = result.get("category")
        if category in ("malicious", "suspicious"):
            found = True
            print(f"- {engine}: {result.get('result')} ({category})")

    if not found:
        print("Срабатываний не найдено.")

def main():
   
    sha256 = "d262de30f1b79581e3e87777de5a3b9ba48ac699ef37c5af065e36d1e5dc0d1c"

    if len(sha256) != 64:
        raise SystemExit("Ошибка: SHA-256 должен быть длиной 64 символа.")

    try:
        report = get_file_report(sha256)

        print("=== Полный JSON ===")
        print(json.dumps(report, indent=2, ensure_ascii=False))

        print()
        print_summary(report)

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "N/A"
        print(f"HTTP ошибка: {e} (status={status})")
        if e.response is not None:
            print("Ответ API:")
            print(e.response.text)
    except requests.exceptions.RequestException as e:
        print("Ошибка сети:", e)
    except RuntimeError as e:
        print("Ошибка конфигурации:", e)

if __name__ == "__main__":
    main()
