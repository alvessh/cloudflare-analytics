import requests
import csv
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os

load_dotenv()

class CloudflareAPI:
    def __init__(self, api_token, timezone_offset=-4):
        self.api_token = api_token
        self.graphql_url = "https://api.cloudflare.com/client/v4/graphql"
        self.rest_url = "https://api.cloudflare.com/client/v4/zones"
        self.timezone = timezone(timedelta(hours=timezone_offset))

    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def get_zones(self):
        headers = self.get_headers()
        zones = []
        page = 1
        per_page = 50

        while True:
            url = f"{self.rest_url}?page={page}&per_page={per_page}"
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()

                zones.extend([{"id": zone["id"], "name": zone["name"]} for zone in data.get("result", [])])

                result_info = data.get("result_info", {})
                if result_info.get("page", 1) >= result_info.get("total_pages", 1):
                    break

                page += 1
            except requests.exceptions.RequestException as e:
                print(f"Erro ao obter zonas: {e}")
                break

        return zones

    def fetch_page_shield_logs(self, zone_id):
        """ Obtém os logs do Page Shield para uma zona específica """
        url = f"{self.rest_url}/{zone_id}/page_shield/scripts"
        logs = []
        page = 1
        per_page = 200

        while True:
            print(f"Buscando Page Shield - Página {page} para zona {zone_id}...")
            try:
                response = requests.get(f"{url}?page={page}&per_page={per_page}", headers=self.get_headers())
                response.raise_for_status()
                data = response.json()

                if not data.get("success", False):
                    print("Erro na resposta da API:", data.get("errors", []))
                    break

                page_logs = data.get("result", [])
                if not page_logs:
                    print(f"Nenhum dado encontrado na página {page} para zona {zone_id}.")
                    break

                logs.extend(page_logs)

                result_info = data.get("result_info", {})
                total_pages = result_info.get("total_pages", 1)

                if page >= total_pages:
                    break  # Sai do loop se já coletou todas as páginas

                page += 1
            except requests.exceptions.RequestException as e:
                print(f"Erro ao buscar logs do Page Shield para zona {zone_id}: {e}")
                break

        return logs
    
    def fetch_firewall_events(self, zone_id, start_time, end_time):
        query = """
        query ($zoneTag: String!, $filter: FirewallEventsAdaptiveFilter_InputObject) {
          viewer {
            zones(filter: { zoneTag: $zoneTag }) {
              firewallEventsAdaptive(
                filter: $filter
                limit: 10000
                orderBy: [datetime_ASC]
              ) {
                action
                clientRequestHTTPHost
                clientAsn
                clientCountryName
                clientIP
                clientRequestPath
                clientRequestQuery
                datetime
                source
                userAgent
              }
            }
          }
        }
        """
        headers = self.get_headers()
        variables = {
            "zoneTag": zone_id,
            "filter": {
                "datetime_geq": start_time.isoformat(),
                "datetime_leq": end_time.isoformat(),
                "action": "managed_challenge",
            },
        }
        try:
            response = requests.post(self.graphql_url, json={"query": query, "variables": variables}, headers=headers)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erro ao buscar eventos: {e}")
            return []
        except ValueError as e:
            print(f"Erro ao interpretar resposta como JSON: {e}")
            return []

        zones = data.get("data", {}).get("viewer", {}).get("zones", [])
        if not zones:
            print(f"Nenhuma zona encontrada para a consulta. Resposta: {data}")
            return []

        return zones[0].get("firewallEventsAdaptive", [])

    def fetch_all_firewall_events(self, zones):
        events = []
        now = datetime.now(self.timezone)

        for zone in zones:
            zone_id = zone["id"]
            zone_name = zone["name"]
            print(f"Buscando eventos para a zona {zone_name} (ID: {zone_id})...")

            for hour_offset in range(2):
                hour_start = now - timedelta(hours=(hour_offset + 1) * 12)
                hour_end = now - timedelta(hours=hour_offset * 12)

                try:
                    hourly_events = self.fetch_firewall_events(zone_id, hour_start, hour_end)
                    if hourly_events:
                        print(f"{len(hourly_events)} eventos encontrados entre {hour_start} e {hour_end}.")
                    else:
                        print(f"Nenhum evento encontrado entre {hour_start} e {hour_end}.")
                    events.extend(hourly_events)
                except Exception as e:
                    print(f"Erro ao buscar eventos para a zona {zone_name} entre {hour_start} e {hour_end}: {e}")

        print(f"Total de eventos coletados: {len(events)}")
        return events


class FirewallEventManager:
    def __init__(self, api_token, output_csv="firewall_events.csv"):
        self.api_token = api_token
        self.output_csv = output_csv
        self.cloudflare_api = CloudflareAPI(api_token)

    def save_events_to_csv(self, events):
        with open(self.output_csv, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "action", "clientRequestHTTPHost", "clientAsn", "clientCountryName",
                "clientIP", "clientRequestPath", "clientRequestQuery", "datetime",
                "source", "userAgent"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(events)

    def fetch_and_save_events(self):
        zones = self.cloudflare_api.get_zones()
        if not zones:
            print("Nenhuma zona disponível. Encerrando.")
            return

        events = self.cloudflare_api.fetch_all_firewall_events(zones)

        if not events:
            print("Nenhum evento encontrado nas últimas 24 horas.")
            return

        self.save_events_to_csv(events)
        print(f"{len(events)} eventos salvos em '{self.output_csv}'.")

class PageShieldManager:
    def __init__(self, api_token, output_csv="page_shield_logs.csv", specific_zone=None):
        self.api_token = api_token
        self.output_csv = output_csv
        self.specific_zone = specific_zone
        self.cloudflare_api = CloudflareAPI(api_token)

    def save_logs_to_csv(self, logs):
        """ Salva os logs do Page Shield em um arquivo CSV """
        with open(self.output_csv, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "URL", "Host", "Primeira Detecção", "Última Detecção", "Hash",
                "Malware Score", "Magecart Score", "Obfuscation Score",
                "Cryptomining Score", "Dataflow Score", "Domínio Malicioso",
                "URL Maliciosa", "Páginas Relacionadas"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for log in logs:
                writer.writerow({
                    "URL": log.get("url", ""),
                    "Host": log.get("host", ""),
                    "Primeira Detecção": log.get("first_seen_at", ""),
                    "Última Detecção": log.get("last_seen_at", ""),
                    "Hash": log.get("hash", ""),
                    "Malware Score": log.get("malware_score", ""),
                    "Magecart Score": log.get("magecart_score", ""),
                    "Obfuscation Score": log.get("obfuscation_score", ""),
                    "Cryptomining Score": log.get("cryptomining_score", ""),
                    "Dataflow Score": log.get("dataflow_score", ""),
                    "Domínio Malicioso": log.get("domain_reported_malicious", ""),
                    "URL Maliciosa": log.get("url_reported_malicious", ""),
                    "Páginas Relacionadas": ", ".join(log.get("page_urls", []))
                })

    def fetch_and_save_logs(self):
        """ Busca e salva os logs do Page Shield para as zonas (ou apenas a zona específica, se fornecida) """
        zones = []

        if self.specific_zone:
            zones.append({"id": self.specific_zone, "name": self.specific_zone})
        else:
            zones = self.cloudflare_api.get_zones()

        if not zones:
            print("Nenhuma zona disponível. Encerrando.")
            return

        all_logs = []
        for zone in zones:
            print(f"Buscando logs do Page Shield para a zona {zone['name']} (ID: {zone['id']})...")
            logs = self.cloudflare_api.fetch_page_shield_logs(zone["id"])
            if logs:
                print(f"{len(logs)} registros encontrados para a zona {zone['name']}.")
                all_logs.extend(logs)
            else:
                print(f"Nenhum log encontrado para a zona {zone['name']}.")

        if not all_logs:
            print("Nenhum dado de Page Shield coletado.")
            return

        self.save_logs_to_csv(all_logs)
        print(f"{len(all_logs)} registros salvos em '{self.output_csv}'.") 

if __name__ == "__main__":
    API_TOKEN = os.getenv("API_TOKEN")
    SPECIFIC_ZONE = os.getenv("SPECIFIC_ZONE")

    if not API_TOKEN:
        print("API_TOKEN não encontrado no arquivo .env.")
    else:
        # event_manager = FirewallEventManager(API_TOKEN)
        # event_manager.fetch_and_save_events()

        shield_manager = PageShieldManager(API_TOKEN, specific_zone=SPECIFIC_ZONE)
        shield_manager.fetch_and_save_logs()