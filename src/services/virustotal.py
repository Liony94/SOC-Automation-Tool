import aiohttp
from src.core.config import settings
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Augmenter le niveau de logging pour le débogage

class VirusTotalService:
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    @staticmethod
    async def check_ip(ip_address: str):
        async with aiohttp.ClientSession() as session:
            headers = {
                "x-apikey": settings.VIRUSTOTAL_API_KEY,
                "accept": "application/json"
            }
            async with session.get(
                f"{VirusTotalService.BASE_URL}/ip_addresses/{ip_address}",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.debug(f"VirusTotal raw response: {data}")
                    attributes = data.get("data", {}).get("attributes", {})
                    logger.debug(f"VirusTotal attributes: {attributes}")
                    
                    last_analysis_stats = attributes.get("last_analysis_stats", {})
                    last_analysis_results = attributes.get("last_analysis_results", {})
                    # Extraction des informations réseau selon la documentation
                    network_info = {
                        "asn": attributes.get("asn", 0),
                        "as_owner": attributes.get("as_owner", "Unknown"),
                        "country": attributes.get("country", "Unknown"),
                        "network": attributes.get("network", "Unknown"),
                        "regional_internet_registry": attributes.get("regional_internet_registry", "Unknown"),
                        "continent": attributes.get("continent", "Unknown"),
                        "network_cidr": attributes.get("network_cidr", "Unknown"),
                        "last_analysis_date": attributes.get("last_analysis_date", None),
                        "last_https_certificate": attributes.get("last_https_certificate", {}),
                        "total_votes": {
                            "harmless": attributes.get("total_votes", {}).get("harmless", 0),
                            "malicious": attributes.get("total_votes", {}).get("malicious", 0)
                        },
                        "reputation": attributes.get("reputation", 0),
                        "whois": attributes.get("whois", "No WHOIS data available"),
                        "whois_date": attributes.get("whois_date", None),
                        "tags": attributes.get("tags", []),
                        "last_modification_date": attributes.get("last_modification_date", None),
                        "threat_categories": attributes.get("categories", []),
                        "popularity_ranks": attributes.get("popularity_ranks", {}),
                        "last_analysis_stats": last_analysis_stats,
                        "last_analysis_results": last_analysis_results
                    }
                    
                    # Compter les résultats malveillants et suspects
                    malicious_count = 0
                    suspicious_count = 0
                    harmless_count = 0
                    
                    for result in last_analysis_results.values():
                        category = result.get("category", "").lower()
                        if category == "malicious":
                            malicious_count += 1
                        elif category == "suspicious":
                            suspicious_count += 1
                        elif category == "harmless":
                            harmless_count += 1
                    
                    logger.debug(f"Counts - Malicious: {malicious_count}, Suspicious: {suspicious_count}, Harmless: {harmless_count}")
                    
                    # Analyse détaillée des résultats
                    analysis_details = {
                        "engines": {},
                        "detection_summary": {
                            "malicious": malicious_count,
                            "suspicious": suspicious_count,
                            "harmless": harmless_count,
                            "undetected": last_analysis_stats.get("undetected", 0),
                            "timeout": last_analysis_stats.get("timeout", 0)
                        }
                    }

                    # Récupérer les détails de chaque moteur d'analyse
                    for engine_name, result in last_analysis_results.items():
                        analysis_details["engines"][engine_name] = {
                            "category": result.get("category", "unknown"),
                            "result": result.get("result", None),
                            "method": result.get("method", "unknown"),
                            "engine_name": result.get("engine_name", engine_name),
                            "engine_version": result.get("engine_version", "unknown")
                        }

                    return {
                        "positives": malicious_count + suspicious_count,
                        "total": sum(last_analysis_stats.values()),
                        "reputation": network_info["reputation"],
                        "last_analysis_stats": analysis_details["detection_summary"],
                        "country": network_info["country"],
                        "continent": network_info["continent"],
                        "as_owner": network_info["as_owner"],
                        "network": network_info["network"],
                        "network_cidr": network_info["network_cidr"],
                        "asn": f"AS{network_info['asn']}",
                        "registry": network_info["regional_internet_registry"],
                        "whois": network_info["whois"],
                        "whois_date": network_info["whois_date"],
                        "community_votes": network_info["total_votes"],
                        "tags": network_info["tags"],
                        "last_analysis_date": network_info["last_analysis_date"],
                        "last_modification_date": network_info["last_modification_date"],
                        "threat_categories": network_info["threat_categories"],
                        "popularity_ranks": network_info["popularity_ranks"],
                        "detailed_analysis": analysis_details["engines"]
                    }
                else:
                    error_text = await response.text()
                    logger.error(f"VirusTotal API error: Status {response.status}, Response: {error_text}")
                    raise Exception(f"Erreur VirusTotal: {response.status}") 