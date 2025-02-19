import logging
from src.services.crowdsec import CrowdSecService
from src.core.risk_levels import RiskLevel
from typing import Dict, Optional
import discord
from discord.ext import commands
from src.core.config import settings

logger = logging.getLogger(__name__)

class ActionService:
    def __init__(self, bot: Optional[commands.Bot] = None):
        self.crowdsec = CrowdSecService()
        self.bot = bot
        try:
            self.alert_channel_id = int(settings.DISCORD_ALERT_CHANNEL_ID) if settings.DISCORD_ALERT_CHANNEL_ID else None
        except (ValueError, TypeError):
            logger.error(f"Invalid DISCORD_ALERT_CHANNEL_ID: {settings.DISCORD_ALERT_CHANNEL_ID}")
            self.alert_channel_id = None

    async def execute_actions(self, ip: str, risk_level: RiskLevel, analysis_data: Dict) -> Dict:
        actions_taken = []
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            # Vérifier si CrowdSec est activé
            if self.crowdsec.enabled:
                # Vérifier si l'IP est déjà dans CrowdSec
                existing_decision = await self.crowdsec.check_ip(ip)
                
                if not existing_decision:
                    # Déterminer la durée du ban selon le niveau de risque
                    duration = "24h" if risk_level == RiskLevel.CRITICAL else "4h"
                    
                    # Construire la raison du ban
                    vt_ratio = analysis_data.get("analysis", {}).get("virustotal", {}).get("detection_ratio", "0/0")
                    abuse_score = analysis_data.get("analysis", {}).get("abuseipdb", {}).get("confidence_score", 0)
                    
                    reason = (
                        f"Automated ban - Risk Level: {risk_level.value} - "
                        f"VT: {vt_ratio}, AbuseIPDB: {abuse_score}%"
                    )
                    
                    # Ajouter la décision dans CrowdSec
                    crowdsec_result = await self.crowdsec.add_decision(
                        ip=ip,
                        duration=duration,
                        reason=reason
                    )
                    
                    if "error" not in crowdsec_result:
                        actions_taken.append(f"IP bloquée dans CrowdSec pour {duration}")
                    
                    # Envoyer une alerte Discord si configuré
                    if self.bot and self.alert_channel_id:
                        try:
                            channel = self.bot.get_channel(self.alert_channel_id)
                            if channel:
                                embed = discord.Embed(
                                    title="🚨 Alerte de Sécurité - IP Malveillante Détectée",
                                    description=f"L'IP {ip} a été automatiquement bloquée",
                                    color=discord.Color.red()
                                )
                                embed.add_field(
                                    name="Niveau de Risque",
                                    value=risk_level.value.upper(),
                                    inline=True
                                )
                                embed.add_field(
                                    name="Durée du Blocage",
                                    value=duration,
                                    inline=True
                                )
                                embed.add_field(
                                    name="Raison",
                                    value=reason,
                                    inline=False
                                )
                                
                                await channel.send(embed=embed)
                                actions_taken.append("Alerte Discord envoyée")
                        except Exception as e:
                            logger.error(f"Erreur lors de l'envoi de l'alerte Discord: {str(e)}")
            else:
                actions_taken.append("CrowdSec non configuré - blocage ignoré")
        
        return {
            "ip": ip,
            "risk_level": risk_level.value,
            "actions_taken": actions_taken
        } 